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
//todo:
// replace locks in extract_entropy extract_entropy_user, and consider account() 


//Locks liberated:
//


// remove _crng_backtrack_protect - it is all protected from backtracks.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//#include "types.h"
#include <stdio.h>
//#include <linux/compiler.h>
//#include <linux/types.h>
//#include <linux/compiler_types.h>
//#include <linux/init.h>
//#include <linux/kdb.h>
#include "knockout.h"
//#include <include/linux/jiffies.h>
//#include <include/linux/log2.h>
//#include <linux/compiler_attributes.h>
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
static struct crng_state primary_crng;

static __u32 input_pool_data[INPUT_POOL_WORDS];
static __u32 blocking_pool_data[OUTPUT_POOL_WORDS];

static struct entropy_store input_pool = {
  .poolinfo = &poolinfo_table[0],
  .name = "input",
  .pool = input_pool_data
};



#ifndef __frontdoor_key
  //#ifdef CONFIG_X86_64
  #define __frontdoor_key( new_key, origin_address )(new_key = (u64)new_key ^ &origin_address ^ &new_key ^ _RET_IP_ ^ _THIS_IP_ )
  //#else
  // #define 
  //#endif
#endif


/* 
 * A keyverse ID must be unique no matter how many threads invoke it at the same time.
 * To do this, we capture the 'who', 'what' 'when' and 'where' of the request into one value
 * Due to the pidgen-hole pirciple any caller who fills these requiremnets, must except to get the same result.
 * If the caller is the same person and getting a keyverse id at the same time 
 * - then they should expect to be identified in the same way, that what the device does.
 *
 */
u64 make_keyverse(char *origin_address, long consumer_ip)
{
  u64 anvil;

  //we have an address on the stack of where the data is going (origin_address)
  //we have the instruciton pointer of who invoked the device driver (consumer_ip)
  //We have our the 'jiffies' which is when the keyverse was created.
  //We have our stack pointer which is what we are using to generate the keyverse. 
  //When combining the; what, who, when, where we have a globally unique u64.

  //User input is combined with the entropy pool state to derive what key material is used for this keyverse.
  //The return address and current insturciton pointer are _RET_IP_ and _THIS_IP_ come from kernel.h:
  //https://elixir.bootlin.com/linux/v3.0/source/include/linux/kernel.h#L80
  //_THIS_IP_ is always going to be the same because &make_keyverse() is in a static location in memory

  //Is this larger than 32 bit?
  if(sizeof(&origin_address) > 4)
  {
    //all 64 bit values adding uniquness to the anvil.
    anvil ^= (u64)consumer_ip ^ (u64)&origin_address ^ (u64)&anvil;
  }else{
    //These addresses are small so we concat.
    //_THIS_IP_ will be the same for the duration of the runtime. 
    //However, _THIS_IP_ is the instruction pointer which is distict for this boot 
    // - and we use this instruction pointer as a bitmast make the lower bits unique.
    anvil ^= ((u32)consumer_ip << 32 | ((u32)&origin_address ^ (u32)_THIS_IP_));
    anvil ^=  ((u32)&origin_address << 32 | (u32)&anvil);
  }
  //Anvil and jiffies shouldn't be anything alike
  //This xor operation will preserve uniqueness. 
  anvil ^= jiffies;

  //A globally unique (maybe universally uniqe) keyverse id has been minted.
  return anvil;
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

//Copy by bit offset.
void  xor_bits( uint8_t dest[], uint8_t source[], int source_len, int bit_offset, int byte_length)
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
      dest[k] ^= (0xffffffff >> (32-(pos))) << source[start_byte+k];
      if(k == byte_length-1)
      {
        //end the array with the bit position compliment
        pos = 32 - (bit_offset%32);
      }else{
              pos = 0;
      }
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


// This only removes locking from the existing mix_pool_bytes() - we want a race conditions
// The underlying mix_pool_bytes is awesome, but the locks around it are not needed with a keypool.
// This one change removes locks from add_timer_randomness, add_input_randomness, add_disk_randomness, and add_interrupt_randomness
// add_timer_randomness add_input_randomness add_disk_randomness are fine becuase they do not contain locks.
static void mix_pool_bytes(struct entropy_store *r, const void *in,
         int nbytes)
{
  _mix_pool_bytes(r, in, nbytes);
}

/*
 * The goal here is to be fast
 * the user needs less 1 block, they only need two words.
 * Lets fill the request as quickly as we can.
 */

u64 get_random_u64(void)
{
  u64 anvil;
  u64 mop;
  u64 seed;
  int key_entry_point;
  uint64_t keyverse = make_keyverse(&anvil, _RET_IP_);
  int entry_point = keyverse % POOL_SIZE_BITS;
  xor_bits( anvil, runtime_entropy, POOL_SIZE, entry_point, sizeof(anvil));

  // XOR over something globally unique.
  // anything in runtime_entropy could be in use.
  // Some of the keyverse isn't known to the caller.
  anvil ^= keyverse;

  if (arch_get_random_seed_long(&seed)) {
    //Ok great, lets start with this value from hardware
    //We don't know if it is good or bad, but it helps.
    anvil ^= seed;

    //cleanup - remove entry point:
    arch_get_random_seed_long(&mop);
  } else {

    // This jumptable pattern follows a similar pattern to the AES counterpart.
    key_entry_point = (int)anvil % POOL_SIZE_BITS;

    //If we choose the same point then we xor the same values.
    //Fall to either side, don't prefer one side.
    if(key_entry_point == entry_point){
      key_entry_point += (key_entry_point % 2) ? 1 : -1;
    }
    //add this source
    xor_bits(&anvil, runtime_entropy, sizeof(runtime_entropy), key_entry_point, sizeof(anvil));

    //Get another point of PRNG to scrub the keypool.
    mop = (u64)runtime_entropy + ((anvil + sizeof(anvil)) % (POOL_SIZE_BITS/8));
  }
  //If the mop came from hardware, we want to scrub it before use.
  //Make sure this mop is unique, more unique is more clean.
  mop ^= keyverse;
  keyverse = 0;
  //cover our tracks, remove entry point
  xor_bits( runtime_entropy + entry_point, mop, sizeof(mop), 0, sizeof(mop));
  entry_point = 0;
  key_entry_point = 0;
  //clean the mop
  mop = 0;
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
  //The caller doesn't know the value of keyverse
  uint64_t keyverse = make_keyverse(&anvil, _RET_IP_);
  int entry_point = keyverse % POOL_SIZE_BITS;
  int key_entry_point = (int)*runtime_entropy + entry_point;
  xor_bits( &anvil, runtime_entropy, POOL_SIZE, key_entry_point, sizeof(anvil));

  // XOR over something globally unique.
  // anything in runtime_entropy could be in use.
  // Some of the keyverse isn't known to the caller.
  anvil ^= (u32)keyverse;

  //Do we have a good source of hardware random values?
  if (arch_get_random_seed_long(&seed)) {
     //Only 32 bits needed
     anvil ^= seed;
     //The other 32 bits are used for cleanup.
     mop = (seed << 32);  
  } else {
    // This jumptable pattern follows a similar pattern to the AES counterpart.
    int key_entry_point = (int)anvil % POOL_SIZE_BITS;

    //If we choose the same point then we xor the same values.
    //Fall to either side, don't prefer one side.
    if(key_entry_point == entry_point){
      key_entry_point += (key_entry_point % 2) ? 1 : -1;
    }
    //add this source
    xor_bits(&anvil, runtime_entropy, POOL_SIZE, key_entry_point, sizeof(anvil));

    //Get another point of PRNG to scrub the keypool.
    mop = (u64)runtime_entropy + ((anvil + sizeof(anvil)) % (POOL_SIZE_BITS/8));
  }
  //If the mop came from hardware, we want to scrub it before use.
  //Make sure this mop is unique, more unique is more clean.
  mop ^= (u32)*(&keyverse+4);
  keyverse = 0;
  //cover our tracks, remove entry point
  xor_bits( runtime_entropy + entry_point, mop, sizeof(mop), 0, sizeof(anvil));
  entry_point = 0;
  key_entry_point = 0;
  //clean the mop
  mop = 0;
  return anvil;
}
/*
 * There are many times when we need another opinion. 
 * Ideally that would come from another source, such as arch_get_random_seed_long()
 * When we don't have a arch_get_random_seed_long, then we'll use ourselves as a source.
 * 
 * Failure is not an option.
 */
u64 get_alternate_rand()
{
  u64 a_few_words;
  //Try every source we know of. Taken from random.c
  if(!arch_get_random_seed_long(&a_few_words))
  {
      if(!arch_get_random_long(&a_few_words))
      {
         a_few_words ^= random_get_entropy();
      }
  }
  if(!a_few_words)
  {
    //Well we know one source that won't let us down:
    a_few_words ^= get_random_u64();
  }
  return a_few_words;
}


/*
 * This function extracts randomness from the Keypool, and
 * returns it in a userspace buffer.
 *
 * This is where users get their entropy from the random.c 
 * device driver (i.e. reading /dev/random)
 */
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes){
    //Check  to see if the request is too small to warrent generating a full block.
    //Speed is an important part of this driver
    //get_random_u32 and get_random_u64 where written to be secure
    if(nbytes <= 0){
      return 0;
    //If we can be fast, lets be fast.
    }else if(nbytes <= 4){
      //Dogfood - get one byte from the pool.
      u32 one_chunk;
      one_chunk ^= get_random_u32();
      memcpy(__user_buf, &one_chunk, nbytes);
      return nbytes;
    }else if(nbytes <= 8){
      //Grab a larger chunk
      u64 two_chunk = get_random_u64();
      memcpy(__user_buf, &two_chunk, nbytes);
      return nbytes;
    }else{
      //Ok, we need somthing bigger, time for OFB.
      uint8_t    local_iv[BLOCK_SIZE];
      AesOfbContext   aesOfb; 
      size_t amountLeft = nbytes;
      int chunk;
      //Take everything about this specific call and merge it into one unique word (2 bytes).
      //User input is combined with the entropy pool state to derive what key material is used for this keyverse.
      uint64_t keyverse = make_keyverse(__user_buf, _RET_IP_);
      

      //For key scheduling purposes, the entropy pool acts as a kind of twist table.
      //The pool is circular, so our starting point can be the last element in the array. 
      int entry_point = keyverse % POOL_SIZE_BITS;
      bitcpy(local_iv, runtime_entropy, POOL_SIZE, entry_point, BLOCK_SIZE);
      //make sure this IV is universally unique, and distinct from any global state.
      (*local_iv) ^= (u64)keyverse;

      //Sure get_alternate_rand() is optional, but anything helps.
      //If we add an additionall call to get_alternate_rand() we will;
      //Increase entropy, introduce uncertity, and reduce already impossilbe collisions.
     // (*(local_iv + 8)) ^= get_alternate_rand();

      //Select the key:
      int key_entry_point = ((int)*local_iv + entry_point) % (POOL_SIZE - BLOCK_SIZE);

      // For AES-OFB the final key is iv^key 
      // - so we wan't to make sure key_entry_point != entry_point
      //Fall to either side, don't prefer one side.
      if(key_entry_point == entry_point){
        key_entry_point += (key_entry_point % 2) ? 1 : -1;
      }

      //Generate one block of PRNG
      AesOfbInitialiseWithKey( &aesOfb, runtime_entropy + key_entry_point, (BLOCK_SIZE/8), local_iv );
      
      //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
      AesOfbOutput( &aesOfb, __user_buf, nbytes);

      //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
      //Encrypt our entropy point with the key material derivied in this local keyverse
      AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), BLOCK_SIZE);
      //Zero out memeory to prevent backtracking
      memzero_explicit(local_iv, sizeof(local_iv));
      entry_point = 0;
      key_entry_point = 0;
      //Cleanup complete 
      //at this point it should not be possilbe to re-create any part of the PRNG stream used.
      return nbytes;
    }
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
    int key_entry_point;
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this keyverse.
    uint64_t keyverse = make_keyverse(__user_buf, _RET_IP_);
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array. 
    int entry_point = keyverse % POOL_SIZE_BITS;
    bitcpy( local_iv, runtime_entropy, POOL_SIZE, entry_point, BLOCK_SIZE);
    
    //make sure this IV is universally unique, and distinct from any global state.
    (* local_iv) ^= keyverse;
    //xor_bits(local_iv, keyverse, 8);

    //get_alternate_rand() optional, but anything helps here.
    //If we add an additionall call to get_alternate_rand() we will;
    //Increase entropy, introduce uncertity, and reduce already impossilbe collisions.
    u64 anvil = get_alternate_rand();
    (* (local_iv + 8)) ^= anvil;

    //Choose which plaintext input we want to use based off of a hard to guess offset 
    //The iv tells us which input 'image' we chose to start the keyverse:
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
        key_entry_point = ((int)*local_iv + image_entry_point) % (POOL_SIZE - BLOCK_SIZE);
        // For AES-OFB the final key is iv^key 
        // - so we wan't to make sure key_entry_point != entry_point
        //Fall to either side, don't prefer one side.
        if(key_entry_point == entry_point){
          key_entry_point += (key_entry_point % 2) ? 1 : -1;
        }
        //Use an outside source to make sure this key is unique.
        //This is one way we can show that this PRNG stream doesn't have a period
        //By including an outside source every block, we ensure an unlimited supply of PRNG.
        (*(runtime_entropy + key_entry_point)) ^= get_alternate_rand();
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
    //Encrypt our entropy point with the key material derivied in this local keyverse
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), chunk);
    memzero_explicit(local_image, sizeof(local_image));
    memzero_explicit(local_iv, sizeof(local_iv));
    entry_point;
    image_entry_point = 0;
    key_entry_point = 0;
    //Cleanup complete, at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
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
  //Globally unique keyverse
  uint64_t keyverse = make_keyverse(&irq, _RET_IP_);
  //Other itterupts are unlikely to choose our same entry_point
  int entry_point = keyverse % (POOL_SIZE - 4);
  uint8_t  *fast_pool;// = this_cpu_ptr(&irq_randomness);
  struct pt_regs    *regs = get_irq_regs();
  unsigned long   now = jiffies;
  //irq_flags contains a few bits, and every bit counts.
  cycles_t    cycles = irq_flags;
  __u32     c_high, j_high;
  __u64     ip = _RET_IP_;
  unsigned long   seed;

  //Taken from random.c - all O(1) operations
  //The interrupt + time gives us 4 bytes.
  if (cycles == 0)
    cycles = get_reg(fast_pool, regs);
  c_high = (sizeof(cycles) > 4) ? cycles >> 32 : 0;
  j_high = (sizeof(now) > 4) ? now >> 32 : 0;
  fast_pool[0] ^= cycles ^ j_high ^ irq;
  fast_pool[1] ^= now ^ c_high;
  fast_pool[2] ^= ip;
  fast_pool[3] ^= (sizeof(ip) > 4) ? ip >> 32 :
    get_reg(fast_pool, regs);

  //fast_pool has captured all of the sources it can.
  //Mixing fast_pool doesn't make it more unique...

  //If we have a hardware rand, use it as a OTP, which will make it harder to guess.
  //add_interrupt_randomness() only makes a single call to an outside random source
  seed ^= get_alternate_rand();
  
  //Seed is 64 bits, so lets squeeze ever bit out of that.
  fast_pool[0] ^= seed;
  fast_pool[2] ^= keyverse;

  //_mix_pool_bytes() is great and all, but this is called a lot, we want somthing faster. 
  //A single O(1) XOR operation is the best we can get to drip the entropy back into the pool
  runtime_entropy[entry_point] ^= fast_pool[0];
  runtime_entropy[entry_point+2] ^= fast_pool[2];

  //If we wanted entry_point to be divided by the bit, then we would have to burn extra cycles:
  //xor_bits(fast_pool, seed, 0, 4);
  //xor_bits(fast_pool, seed+4, 0, 4);
  //Now add a drop of entropy to the pool - it is 1/POOL_SIZE_BITS chance of an overwrite
  //xor_bits(runtime_entropy, fast_pool, entry_point, fast_pool, 4)
}

static void crng_reseed(struct crng_state *crng, struct entropy_store *r)
{
  AesOfbContext   aesOfb; 
  unsigned long flags;
  int crng_init;
  int   i, num;
  uint8_t local_iv[BLOCK_SIZE];
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
    u64 rv;
    rv ^= get_alternate_rand();
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
    /*invalidate_batched_entropy();
    numa_crng_init();
    crng_init = 2;
    process_random_ready_list();
    //wake_up_interruptible(&crng_init_wait);
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
    }*/
  }
}


/*
 * Credit (or debit) the entropy store with n bits of entropy.
 * Use credit_entropy_bits_safe() if the value comes from userspace
 * or otherwise should be checked for extreme values.
 */
static void credit_entropy_bits(struct entropy_store *r, int nbits)
{
  int entropy_count, orig, has_initialized = 0;
  const int pool_size = r->poolinfo->poolfracbits;
  int nfrac = nbits << ENTROPY_SHIFT;

  if (!nbits)
    return;

retry:
  entropy_count = orig = READ_ONCE(r->entropy_count);
  if (nfrac < 0) {
    /* Debit */
    entropy_count += nfrac;
  } else {
    /*
     * Credit: we have to account for the possibility of
     * overwriting already present entropy.  Even in the
     * ideal case of pure Shannon entropy, new contributions
     * approach the full value asymptotically:
     *
     * entropy <- entropy + (pool_size - entropy) *
     *  (1 - exp(-add_entropy/pool_size))
     *
     * For add_entropy <= pool_size/2 then
     * (1 - exp(-add_entropy/pool_size)) >=
     *    (add_entropy/pool_size)*0.7869...
     * so we can approximate the exponential with
     * 3/4*add_entropy/pool_size and still be on the
     * safe side by adding at most pool_size/2 at a time.
     *
     * The use of pool_size-2 in the while statement is to
     * prevent rounding artifacts from making the loop
     * arbitrarily long; this limits the loop to log2(pool_size)*2
     * turns no matter how large nbits is.
     */
    int pnfrac = nfrac;
    const int s = r->poolinfo->poolbitshift + ENTROPY_SHIFT + 2;
    /* The +2 corresponds to the /4 in the denominator */

    do {
      unsigned int anfrac = min(pnfrac, pool_size/2);
      unsigned int add =
        ((pool_size - entropy_count)*anfrac*3) >> s;

      entropy_count += add;
      pnfrac -= anfrac;
    } while (unlikely(entropy_count < pool_size-2 && pnfrac));
  }

  if (unlikely(entropy_count < 0)) {
    pr_warn("random: negative entropy/overflow: pool %s count %d\n",
      r->name, entropy_count);
    WARN_ON(1);
    entropy_count = 0;
  } else if (entropy_count > pool_size)
    entropy_count = pool_size;
  if ( !r->initialized &&
      (entropy_count >> ENTROPY_SHIFT) > 128)
    has_initialized = 1;
  if (cmpxchg(&r->entropy_count, orig, entropy_count) != orig)
    goto retry;

  if (has_initialized) {
    r->initialized = 1;
    //wake_up_interruptible(&random_read_wait);
    //kill_fasync(&fasync, SIGIO, POLL_IN);
  }

  trace_credit_entropy_bits(r->name, nbits,
          entropy_count >> ENTROPY_SHIFT, _RET_IP_);

}



static ssize_t
_random_read(int nonblock, char __user *buf, size_t nbytes)
{
  return extract_crng_user(buf, nbytes);
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
  crng_reseed(file, runtime_entropy);
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
