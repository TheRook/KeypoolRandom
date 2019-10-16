// Keypool Random
//
// This main.c file builds a new extract_crng_user() method which is used by /dev/random.
//  - https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L1120
//
// This file includes other code to get extract_crng_user()
// works on mac or linux using gcc
//
// to build:
// ./build.sh
// to run:
// ./poolrand
// 

// remove _crng_backtrack_protect - it is all protected from backtracks.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//#include "types.h"
//#include <stdio.h>
//#include <linux/compiler.h>
#include <linux/types.h>
//#include <linux/compiler_types.h>
#include <linux/init.h>
#include <linux/kdb.h>
#include <include/linux/jiffies.h>
#include <include/linux/log2.h>
#include <linux/compiler_attributes.h>
//#include <trace/events/random.h>
//#include </include/linux/lcm.h>


#include <stdlib.h>
//#include <stdint.h>
//#include <string.h>
#include "WjCryptLib/lib/WjCryptLib_AesOfb.h"
#include <time.h>



//#include "include/linux/types.h"

//#include "include/linux/compiler_attributes.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINITIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __min
   #define __min( x, y )  (((x) < (y))?(x):(y))
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define BUFFER_SIZE             1024
#define BLOCK_SIZE              256
#define BLOCK_SIZE_BITS         BLOCK_SIZE * 8
#define POOL_SIZE               BLOCK_SIZE * 4
#define POOL_SIZE_BITS          BLOCK_SIZE * 8
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Global runtime entropy
uint8_t runtime_entropy[POOL_SIZE];


/* The session is a word (2-bytes) that represents who and where.
 * One caller cannot try to fill the same bucket at the same time.
 * Due to this pidgen-hole priciple, the resulting session will be unique for all users.
 */
uint64_t get_session(uint8_t *origin)
{
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this session.
    uint64_t session = jiffies + (uint64_t) &origin;

    //struct timespec starttime;
    //Lets figure out when this is as accuralty as possilbe.
    //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &starttime);

    //If you xor two strings that are identical they cancle out.
    //we have already taken time ^ address,  xoring another address is less than ideal. 
    //adding an address will make this value more unqiue without cancling an operation.
    session ^= (uint64_t) &session;

    return session;
}

int load_file(uint8_t dest[], int len)
{
  int ret = 0;
  FILE *seed_file;
  seed_file = fopen("seed", "r");
  if(seed_file != NULL)
  {
     fread(dest, 1, len, seed_file);
     ret = 1;
  }
  return ret;
}

void xor_bits( uint8_t dest[], uint8_t source[], int source_len, int bit_offset, int byte_length)
{
    for(int i =0; i < len; i++)
    {
       dest[i] ^= source[i]; 
    }
}

//Copy by bit offset.
void  bitcpy( uint8_t dest[], uint8_t source[], int source_len, int bit_offset, int byte_length)
{
  int start_byte = bit_offset/32;        //The start byte to start the copy
  int pos = bit_offset%32;      //The start bit within the first byte
  for(int k = 0; k < byte_length; k++)
  {
      //Treat the source as a circular buffer.          
      if(start_byte + k > source_len)
      {
         start_byte = 0;
        if(k > source_len)
        {
            //Should not happen.
            break;
        }
      }
      dest[k] = (0xffffffff >> (32-(pos))) << source[start_byte+k];
      if(k == byte_length-1)
      {
        //end the array with the bit position compliment
        pos = 32 - (bit_offset%32);
      }else{
              pos = 0;
      }
  }
}

/*
 * This function extracts randomness from the Keypool, and
 * returns it in a userspace buffer.
 *
 * This is where users get their entropy from the random.c 
 * device driver (i.e. reading /dev/random)
 */
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes){
    //uint32_t    local_key[BLOCK_SIZE];
    uint8_t    local_iv[BLOCK_SIZE];
    AesOfbContext   aesOfb; 
    size_t amountLeft = nbytes;
    int chunk;
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this session.
    uint64_t session = get_session(__user_buf);
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array. 
    int entry_point = session % POOL_SIZE_BITS;
    bitcpy(local_iv, runtime_entropy, POOL_SIZE, entry_point, BLOCK_SIZE);
    //make sure this IV is universally unique, and distinct from any global state.
    (u64)local_iv[0] ^= session;

    //Sure get_alternate_rand() is optional, but anything helps.
    //If we add an additionall call to get_alternate_rand() we will;
    //Increase entropy, introduce uncertity, and reduce already impossilbe collisions.
    (u64)local_iv[8] ^= get_alternate_rand();

    //Select the key:
    int key_entry_point = ((int)*local_iv + entry_point) % (POOL_SIZE - BLOCK_SIZE);
    //Generate one block of PRNG
    AesOfbInitialiseWithKey( &aesOfb, runtime_entropy + key_entry_point, (BLOCK_SIZE/8), local_iv );
    
    //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
    AesOfbOutput( &aesOfb, __user_buf, nbytes);

    //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
    //Encrypt our entropy point with the key material derivied in this local session
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), BLOCK_SIZE);
    //Zero out memeory to prevent backtracking
    memzero_explicit(local_iv, sizeof(local_iv));
    entry_point = 0;
    key_entry_point = 0;
    seed = 0;
    //Cleanup complete 
    //at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
}

// This is the /dev/urandom variant.
// it is simlar to the algorithm above, but more time is spent procuring stronger key mateiral.
// the user is willing to wait, so we'll do our very best.
// when this method completes, the keypool as a whole is better off, as it will be re-scheduled.
static ssize_t extract_crng_user_unlimited(uint8_t *__user_buf, size_t nbytes){
    //uint32_t    local_key[BLOCK_SIZE];
    uint8_t    local_iv[BLOCK_SIZE];
    uint8_t    local_image[BLOCK_SIZE];
    AesOfbContext   aesOfb; 
    size_t amountLeft = nbytes;
    int chunk;
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this session.
    uint64_t session = get_session(__user_buf);
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array. 
    int entry_point = session % POOL_SIZE_BITS;
    bitcpy( local_iv, runtime_entropy, POOL_SIZE, entry_point, BLOCK_SIZE);
    
    //make sure this IV is universally unique, and distinct from any global state.
    (b64)local_iv[0] ^= session;
    //xor_bits(local_iv, session, 8);

    //get_alternate_rand() optional, but anything helps here.
    //If we add an additionall call to get_alternate_rand() we will;
    //Increase entropy, introduce uncertity, and reduce already impossilbe collisions.
    u64 seed = get_alternate_rand();
    //xor_bits(local_iv+8, seed, 8);
    (u64)local_iv[8] ^= seed;
    //Choose which plaintext input we want to use based off of a hard to guess offset 
    //The iv tells us which input 'image' we chose to start the session:
    int image_entry_point = (((int)*local_iv + entry_point) % POOL_SIZE_BITS);
    bitcpy( local_image, runtime_entropy, POOL_SIZE, image_entry_point, BLOCK_SIZE);
    //The key, IV and Image will tumble for as long as they need, and copy out PRNG to the user. 
    while( amountLeft > 0 )
    {
        chunk = __min( amountLeft, BLOCK_SIZE );
        //rescheudle they key each round
        //Follow the twist, the iv we chose tells us which key to use
        //This routine needs the hardest to guess key in constant time.
        //we add the image_entry_point to avoid using the same (iv, key) combination - which still shouldn't happen.
        int key_entry_point = ((int)*local_iv + image_entry_point) % (POOL_SIZE - BLOCK_SIZE);
        
        //Use an outside source to make sure this key is unique.
        //This is one way we can show that this PRNG stream doesn't have a period
        //By including an outside source every block, we ensure an unlimited supply of PRNG.
        (u64)runtime_entropy[key_entry_point] ^= get_alternate_rand();
        //Generate one block of PRNG
        AesOfbInitialiseWithKey( &aesOfb, runtime_entropy + key_entry_point, (BLOCK_SIZE/8), local_iv );
        AesOfbOutput( &aesOfb, local_image, chunk);
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        memcpy( __user_buf + (nbytes - amountLeft), local_image, chunk);
        //This is the resulting IV unused from AES-OFB, intened to be used in the next round:
        memcpy( local_iv, aesOfb.CurrentCipherBlock, BLOCK_SIZE);
        amountLeft -= chunk;
        //At the end of the loop we get:
        //The cipher text from this round is in local_image, which in the input for the next round
        //The IV is a PRNG feedback as per the OFB spec - this is consistant
        //A new secret key is re-chosen each round, the new IV is used to choose the new key.
        //Using an IV as an index insures this instance has a key that is unkown to others - at no extra cost O(1).
    }
    //Cover our tracks.
    //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
    //Encrypt our entropy point with the key material derivied in this local session
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), chunk);
    memzero_explicit(local_image, sizeof(local_image));
    memzero_explicit(local_iv, sizeof(local_iv));
    seed = 0;
    entry_point;
    image_entry_point = 0;
    key_entry_point = 0;
    //Cleanup complete, at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
}

/*
 * There are many times when we need another opinion. 
 * Ideally that would come from another source, such as arch_get_random_seed_long()
 * When we don't have a arch_get_random_seed_long, then we'll use ourselves as a source.
 * 
 * Failure is not an option.
 */
u64 get_alternate_rand(void)
{
  u64 a_few_words = 0;
  //Try every source we know of. Taken from random.c
  if(!arch_get_random_seed_long(&a_few_words))
  {
      if(!arch_get_random_long(&a_few_words))
      {
         a_few_words = random_get_entropy();
      }
  }
  if(!a_few_words)
  {
    //Well we know one source that won't let us down:
    a_few_words = get_random_u64();
  }
  return a_few_words;
}

/*
 * The goal here is to be fast
 * the user needs less 1 block, they only need two words.
 * Lets fill the request as quickly as we can.
 */

u64 get_random_u64(void)
{
  long seed;
  u64 anvil;
  int mop_entry_point;
  uint64_t session = get_session(&anvil);
  int entry_point = session % POOL_SIZE_BITS;
  bitcpy( anvil, runtime_entropy, POOL_SIZE, entry_point, sizeof(anvil));

  if (arch_get_random_seed_long(&seed)) {
     xor_bits(anvil, seed, 0, sizeof(anvil));
     arch_get_random_seed_long(&seed);
     xor_bits(anvil, seed, 4, sizeof(anvil));
     arch_get_random_seed_long(&seed);
     //cleanup - remove entry point:
     xor_bits( runtime_entropy + entry_point, seed, sizeof(seed));
     //double-tap to get rid of the lower bits:
     arch_get_random_seed_long(&seed);
     //cleanup - remove entry point:
     xor_bits( runtime_entropy + entry_point + sizeof(seed), seed, sizeof(seed));
  } else {
    // XOR over something globally unique.
    // The session isn't known to the caller.
    // This jumptable pattern follows a similar pattern to the AES counterpart.
    xor_bits( anvil, runtime_entropy, entry_point, session, sizeof(anvil));
    // add the next chunk:
    xor_bits( anvil, runtime_entropy + entry_point + sizeof(anvil), sizeof(anvil));
    //Get another point of PRNG to scrub this value.
    mop_entry_point =  anvil % POOL_SIZE_BITS;
    xor_bits( anvil, runtime_entropy + mop_entry_point, sizeof(anvil));
    //cleanup - remove entry point
    xor_bits( runtime_entropy + entry_point, anvil, sizeof(anvil));
    mop_entry_point = 0;
  }
  //cover our tracks.
  //No one will know what this entry point was, 
  //or what it's value was before or after invocation.
  entry_point = 0;
  return anvil;
}

/* 
 * we want to return just one byte as quickly as possilbe. 
 */
u32 get_random_u32(void)
{
  u32 anvil;
  u32 mop;
  long seed;
  int mop_entry_point;
  //The caller doesn't know the value of session
  uint64_t session = get_session(&anvil);
  int entry_point = session % POOL_SIZE_BITS;
  int key_entry_point = (int)*runtime_entropy + entry_point;
  bitcpy( &anvil, runtime_entropy, POOL_SIZE, key_entry_point, sizeof(anvil));

  //Do we have a good source of hardware random values?
  if (arch_get_random_seed_long(&seed)) {
     //Only 32 bits needed
     xor_bits(&anvil, seed, 0, sizeof(anvil));
     //Get another chunk to fix the keypool:
     arch_get_random_seed_long(&seed);
     //cleanup - remove entry point
     xor_bits( runtime_entropy + entry_point, seed, sizeof(anvil));
  } else {
    // XOR over something globally unique.
    // The session isn't known to the caller.
    xor_bits( &anvil, runtime_entropy, entry_point, session, sizeof(anvil));
    // add the next chunk:
    xor_bits( &anvil, runtime_entropy + entry_point + sizeof(anvil), sizeof(anvil));
    //Get another point of PRNG to scrub this value.
    mop_entry_point =  anvil % POOL_SIZE_BITS;
    xor_bits( &anvil, runtime_entropy + mop_entry_point, sizeof(anvil));
    //cleanup - remove entry point
    xor_bits( runtime_entropy + entry_point,anvil , sizeof(anvil));
    mop_entry_point = 0;
  }
  //cover our tracks:
  entry_point = 0;
  key_entry_point = 0;
  return anvil;
}

/* This function is in fact called more times than I have ever used a phone.
 * lets keep this funciton as light as possilbe, and move more weight to extract_crng_user()
 * if we need to add more computation, then the user requesting the PRNG should pay the price
 * any logic added here, means the entire system pays a price. 
 * Choose your operations wisely.
 *
 * fast_mix is fast in name only - mixing can also be handled with encryption.
 *
 */
//If there is one function to make lockless, this is the one
void add_interrupt_randomness(int irq, int irq_flags)
{
  //Globally unique session
  uint64_t session = get_session(&irq);
  //Other itterupts are unlikely to choose our same entry_point
  int entry_point = session % (POOL_SIZE - 4);
  uint8_t  *fast_pool = this_cpu_ptr(&irq_randomness);
  struct pt_regs    *regs = get_irq_regs();
  unsigned long   now = jiffies;
  cycles_t    cycles = random_get_entropy();
  __u32     c_high, j_high;
  __u64     ip;
  unsigned long   seed;
  int     credit = 0;

  //Taken from random.c - all O(1) operations
  //The interrupt + time gives us 4 bytes.
  if (cycles == 0)
    cycles = get_reg(fast_pool, regs);
  c_high = (sizeof(cycles) > 4) ? cycles >> 32 : 0;
  j_high = (sizeof(now) > 4) ? now >> 32 : 0;
  fast_pool[0] ^= cycles ^ j_high ^ irq;
  fast_pool[1] ^= now ^ c_high;
  ip = regs ? instruction_pointer(regs) : _RET_IP_;
  fast_pool[2] ^= ip;
  fast_pool[3] ^= (sizeof(ip) > 4) ? ip >> 32 :
    get_reg(fast_pool, regs);

  //If we have a hardware rand, use it as a OTP
  seed = get_alternate_rand();
  
  //Seed is 64 bits, so lets squeeze ever bit out of that.
  (u32)fast_pool[0] ^= seed;
  (u32)fast_pool[0] ^= seed + 4;

  //Drip the entropy back into the pool
  (u32)runtime_entropy[entry_point] ^= fast_pool;

  //If we wanted entry_point to be divided by the bit, then we would have to burn extra cycles:
  //xor_bits(fast_pool, seed, 0, 4);
  //xor_bits(fast_pool, seed+4, 0, 4);
  //Now add a drop of entropy to the pool - it is 1/POOL_SIZE_BITS chance of an overwrite
  //xor_bits(runtime_entropy, fast_pool, entry_point, fast_pool, 4)
}

static void crng_reseed(struct crng_state *crng, struct entropy_store *r)
{
  unsigned long flags;
  int   i, num;
  uint8_t local_iv[BLOCK_SIZE]
  union {
    __u8  block[BLOCK_SIZE];
    __u32 key[8];
  } buf;

  // fetch an IV in the current state.
  extract_crng_user(&local_iv, BLOCK_SIZE);

  //Generate a secure key:
  if (r) {
    num = extract_crng_user(&buf, BLOCK_SIZE);
    if (num == 0)
      return;
  } else {
    _extract_crng(&primary_crng, buf.block);
  }
  for (i = 0; i < 8; i++) {
    unsigned long rv;
    rv = get_alternate_rand();
    crng->state[i+4] ^= buf.key[i] ^ rv;
  }

  //We used some unclean hardware input, lets mix the pool
  mix_pool_bytes(crng, runtime_entropy, POOL_SIZE);

  //encrypt the entire entropy pool with the new key:
  AesOfbInitialiseWithKey( &aesOfb, crng->state, (BLOCK_SIZE/8), local_iv );
  //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
  AesOfbOutput( &aesOfb, runtime_entropy, POOL_SIZE); 

  memzero_explicit(&buf, sizeof(buf));
  crng->init_time = jiffies;
  if (crng == &primary_crng && crng_init < 2) {
    invalidate_batched_entropy();
    numa_crng_init();
    crng_init = 2;
    process_random_ready_list();
    wake_up_interruptible(&crng_init_wait);
    pr_notice("random: crng init done\n");
    if (unseeded_warning.missed) {
      pr_notice("random: %d get_random_xx warning(s) missed "
          "due to ratelimiting\n",
          unseeded_warning.missed);
      unseeded_warning.missed = 0;
    }
    if (urandom_warning.missed) {
      pr_notice("random: %d urandom warning(s) missed "
          "due to ratelimiting\n",
          urandom_warning.missed);
      urandom_warning.missed = 0;
    }
  }
}

// This only removes locking from the existing mix_pool_bytes() - we want a race conditions
// The underlying mix_pool_bytes is awesome, but the locks around it are not needed with a keypool.
// This one change removes locks from add_timer_randomness, add_input_randomness, add_disk_randomness, and add_interrupt_randomness
// add_timer_randomness add_input_randomness add_disk_randomness are fine becuase they do not contain locks.
static void mix_pool_bytes(struct entropy_store *r, const void *in,
         int nbytes)
{
  _mix_pool_bytes(r, in, bytes);
}

// no blocking
static ssize_t
random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
  return extract_crng_user(buf, nbytes);
}

static ssize_t
urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
  //The user is expecting to get the best restuls.
  //Watch out, unlimited is coming through - lets tidy the place up. 
  crng_reseed(file, runtime_etropy);
  //This is a non-blocking device so we are not going to wait for the pool to fill. 
  //We will respect the users wishes, and spend time to produce the best output.
  return extract_crng_user_unlimited(buf, nbytes);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  main
//
//  Program entry point
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    main
    (
        int             ArgC,
        char**          ArgV
    )
{
    uint8_t        local_block[BLOCK_SIZE*2];
    
    //Assume this is the normal startup procedure from the kernel.
    load_file(runtime_entropy, POOL_SIZE);
    //let's assume the entrpy pool is the same state as a running linux kernel
    //start empty
    memset(local_block, 0, sizeof local_block); 
    
    //lets fill a request
    extract_crng_user(local_block, BLOCK_SIZE*2);
    for (int i = 0; i < BLOCK_SIZE*2; i++)
    {
            printf("%1x", local_block[i]);
     }
    return 0;
}
