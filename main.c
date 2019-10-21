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

//Locks liberated:
//... todo
// remove _crng_backtrack_protect - it is all protected from backtracks.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include "knockout.h"
#include "WjCryptLib/lib/WjCryptLib_AesOfb.h"

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

#define ZERO_PAGE               0
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


//todo covert make_gate_key() into macro... 
#ifndef _gate_key
  #define _gate_key( new_key, origin_address )(new_key = (u64)new_key ^ &origin_address ^ &new_key ^ _RET_IP_ ^ _THIS_IP_ )
  //#else
  // #define 
  //#endif
#endif


/* 
 * A gate_key ID must be unique no matter how many threads invoke it at the same time.
 * To do this, we capture the 'who', 'what' 'when' and 'where' of the request into one value
 * Due to the pidgen-hole pirciple any caller who fills these requiremnets, must except to get the same result.
 * If the caller is the same person and getting a gate_key id at the same time 
 * - then they should expect to be identified in the same way, that what the device does.
 *
 */
u64 make_gate_key(char *origin_address, long consumer_ip)
{
  u64 anvil;

  //we have an address on the stack of where the data is going (origin_address)
  //we have the instruciton pointer of who invoked the device driver (consumer_ip)
  //We have our the 'jiffies' which is when the gate_key was created.
  //We have our stack pointer which is what we are using to generate the gate_key. 
  //When combining the; what, who, when, where we have a globally unique u64.

  //User input is combined with the entropy pool state to derive what key material is used for this gate_key.
  //The return address and current insturciton pointer are _RET_IP_ and _THIS_IP_ come from kernel.h:
  //https://elixir.bootlin.com/linux/v3.0/source/include/linux/kernel.h#L80
  //_THIS_IP_ is always going to be the same because &make_gate_key() is in a static location in memory

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
    anvil ^= ((u32)&origin_address << 32 | (u32)&anvil);
  }
  //Anvil and jiffies shouldn't be anything alike
  //This xor operation will preserve uniqueness. 
  anvil ^= jiffies;

  //A globally unique (maybe universally uniqe) gate_key id has been minted.
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
      *(dest + k) ^= (0xffffffff >> (32-(pos))) << source[start_byte+k];
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
  u64 anvil __latent_entropy;
  u64 mop __latent_entropy;
  u64 seed;
  int key_entry_point;
  uint64_t gate_key = make_gate_key(&anvil, _RET_IP_);
  ////int entry_point = gate_key % POOL_SIZE_BITS;
  ////xor_bits( anvil, runtime_entropy, POOL_SIZE, entry_point, sizeof(anvil));
  int entry_point = _unique_key(&anvil, gate_key, 0, sizeof(anvil));
  // XOR over something globally unique.
  // anything in runtime_entropy could be in use.
  // Some of the gate_key isn't known to the caller.
  //anvil ^= gate_key;

  if (arch_get_random_seed_long(&seed)) {
    //Ok great, lets start with this value from hardware
    //We don't know if it is good or bad, but it helps.
    anvil ^= seed;
    //cleanup - remove entry point:
    arch_get_random_seed_long(&seed);
    mop ^= seed;
  } else {

    // This jumptable pattern follows a similar pattern to the AES counterpart.
    ////key_entry_point = (int)anvil % POOL_SIZE_BITS;
    key_entry_point = _unique_key(&anvil, gate_key, entry_point, sizeof(anvil));

    //Get another point of PRNG to scrub the keypool.
    _unique_key(&mop, gate_key, key_entry_point, sizeof(mop));
  }
  //If the mop came from hardware, we want to scrub it before use.
  //Make sure this mop is unique, more unique is more clean.
  //mop ^= gate_key;
  gate_key = 0;
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
  u32 anvil __latent_entropy;
  u32 mop __latent_entropy;
  long seed;
  int key_entry_point;
  int mop_entry_point;
  //The caller doesn't know the value of gate_key
  uint64_t gate_key = make_gate_key(&anvil, _RET_IP_);
  int entry_point = _unique_key(&anvil, gate_key, 0, sizeof(anvil));

  //Do we have a good source of hardware random values?
  if (arch_get_random_seed_long(&seed)) {
     //Only 32 bits needed
     anvil ^= seed;
     //The other 32 bits are used for cleanup.
     mop ^= (seed << 32);  
  } else {
    // This jumptable pattern follows a similar pattern to the AES counterpart.
    // We want two distinct points within the key pool.
    key_entry_point = _unique_key(&anvil, gate_key, entry_point, sizeof(anvil));
    //Get another point of PRNG to scrub the keypool.
    _unique_key(&mop, gate_key, key_entry_point, sizeof(mop));
  }
  //If the mop came from hardware, we want to scrub it before use.
  //Make sure this mop is unique, more unique is more clean.
  mop ^= (u32)*(&gate_key+4);
  gate_key = 0;
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
  u64 a_few_words __latent_entropy;
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
The race condition in get_universally_unique_key() is intentional.
We XOR some new uncertity into a global buffer that is being acted upon by other threads. 
If the new uncertity is applied, then the resulting value is more unique than previous invokation.
If the new uncertity isn't applied, then this was due to new uncertity being introdued to the global buffer.
We make sure our local copy is augmented from the global state to insure a univerally unique state.
Every (offset % POOL_SIZE) produes a 1/POOL_SIZE chase where two get_universally_unique_key() would return the same state. 
no two threads can ever have the same gate_key - so the result is unique.
*/
int _unique_key(uint8_t uu_key[], u64 gate_key, int last_jump, int nbytes)
{
  //Jump table, use hte last point as the next point.
  int entry_point = (int)runtime_entropy[last_jump] % POOL_SIZE_BITS;
  //There is a 1/POOL_SIZE_BITS chance well jump to the same spot
  if(entry_point == last_jump)
  {
     int shift = nbytes * 8;
     //Protective, make sure that we will pick a unique jump offset.
     if(shift >= POOL_SIZE_BITS){
       //Avoid a ones-complement overflow 
       shift = POOL_SIZE_BITS - 1;
     }
     //filp a coin and go someplace new and interesting: 
     if(runtime_entropy[0] % 2)
     {
        entry_point += shift;
     }else{
        entry_point -= shift;
     }
     //Make sure we are in range.
     entry_point %= POOL_SIZE_BITS;
  }
  int entry_byte_boundry = entry_point/8;
  //Derive uncertity by modifying a global buffer
  runtime_entropy[entry_byte_boundry + 1] ^= get_alternate_rand();
  //make a local copy, which may fall between a byte boundry
  xor_bits(uu_key, runtime_entropy, POOL_SIZE, entry_point, nbytes);
  //make sure this key is distinct from any global state.
  //we use uu_key+5 instead of +4 to account for the entry_byte_boundry.
  if(nbytes >= 9){
    uu_key[5] ^= (u64)gate_key;
  }else{
    uu_key[0] ^= (u64)gate_key;
  }
  //return the next offset.
  return entry_point;
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
      u32 one_chunk __latent_entropy;
      one_chunk ^= get_random_u32();
      memcpy(__user_buf, &one_chunk, nbytes);
      return nbytes;
    }else if(nbytes <= 8){
      //Grab a larger chunk
      u64 two_chunk __latent_entropy;
      two_chunk ^= get_random_u64();
      memcpy(__user_buf, &two_chunk, nbytes);
      return nbytes;
    }else{
      //Ok, we need somthing bigger, time for OFB.
      uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
      uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
      AesOfbContext   aesOfb; 
      size_t amountLeft = nbytes;
      int chunk;
      //Take everything about this specific call and merge it into one unique word (2 bytes).
      //User input is combined with the entropy pool state to derive what key material is used for this gate_key.
      uint64_t gate_key = make_gate_key(__user_buf, _RET_IP_);
      
      //For key scheduling purposes, the entropy pool acts as a kind of twist table.
      //The pool is circular, so our starting point can be the last element in the array. 
      int entry_point = _unique_key(local_iv, gate_key, 0, BLOCK_SIZE);

      //Select the key:
      _unique_key(local_key, gate_key, entry_point, BLOCK_SIZE);

      //Generate one block of PRNG
      AesOfbInitialiseWithKey( &aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
      
      //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
      AesOfbOutput( &aesOfb, __user_buf, nbytes);

      //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
      //Encrypt our entropy point with the key material derivied in this local gate_key
      AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), BLOCK_SIZE);
      //Zero out memeory to prevent backtracking
      memzero_explicit(local_iv, sizeof(local_iv));
      entry_point = 0;
      //Cleanup complete 
      //at this point it should not be possilbe to re-create any part of the PRNG stream used.
      return nbytes;
    }
}

// This is the /dev/urandom variant.
// it is simlar to the algorithm above, but more time is spent procuring stronger key mateiral.
// the user is willing to wait, so we'll do our very best.
// when this method completes, the keypool as a whole is better off, as it will be re-scheduled.
static ssize_t extract_crng_user_unlimited(uint8_t *__user_buf, size_t nbytes)
{
    uint8_t   local_key[BLOCK_SIZE] __latent_entropy;
    uint8_t   local_iv[BLOCK_SIZE] __latent_entropy;
    uint8_t   local_image[BLOCK_SIZE] __latent_entropy;
    AesOfbContext   aesOfb;
    size_t amountLeft = nbytes;
    int chunk;
    int key_entry_point;
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this gate_key.
    uint64_t gate_key = make_gate_key(__user_buf, _RET_IP_);
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array.
    int entry_point = _unique_key(local_iv, gate_key, 0, BLOCK_SIZE);

    int image_entry_point = _unique_key(local_image, gate_key, entry_point, BLOCK_SIZE);
    //The key, IV and Image will tumble for as long as they need, and copy out PRNG to the user. 
    while( amountLeft > 0 )
    {
        chunk = __min( amountLeft, BLOCK_SIZE );
        //rescheudle they key each round
        //Follow the twist, the iv we chose tells us which key to use
        //This routine needs the hardest to guess key in constant time.
        key_entry_point = _unique_key(local_key, gate_key, image_entry_point, BLOCK_SIZE);

        //Use an outside source to make sure this key is unique.
        //This is one way we can show that this PRNG stream doesn't have a period
        //By including an outside source every block, we ensure an unlimited supply of PRNG.
        //Even if a hardware rand isn't available, we'll generate a random value without AES.
        //This step raises the bar, and some PRNGs will use zeros here:
        *local_image ^= get_alternate_rand();
        *(local_image + 4) ^= get_alternate_rand();

        //Generate one block of PRNG
        AesOfbInitialiseWithKey( &aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
        AesOfbOutput( &aesOfb, local_image, chunk);
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        memcpy( __user_buf + (nbytes - amountLeft), local_image, chunk);
        amountLeft -= chunk;
        //More work?
        if(amountLeft > 0)
        {
          //At the end of the loop we get:
          //The cipher text from this round is in local_image, which in the input for the next round
          //The IV is a PRNG feedback as per the OFB spec - this is consistant
          //A new secret key is re-chosen each round, the new IV is used to choose the new key.
          //Using an IV as an index insures this instance has a key that is unkown to others - at no extra cost O(1).

          //This is the resulting IV unused from AES-OFB, intened to be used in the next round:
          memcpy( local_iv, aesOfb.CurrentCipherBlock, BLOCK_SIZE);
        }
     }
    //Cover our tracks.
    //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
    //Encrypt our entropy point with the key material derivied in this local gate_key
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), chunk);
    memzero_explicit(local_image, sizeof(local_image));
    memzero_explicit(local_iv, sizeof(local_iv));
    entry_point = 0;
    image_entry_point = 0;
    key_entry_point = 0;
    //Cleanup complete, at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
}

/*
 * Credit (or debit) the entropy store with n bits of entropy.
 * Use credit_entropy_bits_safe() if the value comes from userspace
 * or otherwise should be checked for extreme values.
 */
static void fast_keypool_addition(void *small_pool, long gate_key, int nbytes)
{
  int entry_point = gate_key % POOL_SIZE_BITS;
  xor_bits(runtime_entropy, small_pool, entry_point, POOL_SIZE, nbytes);
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
  //Globally unique gate_key
  uint64_t gate_key = make_gate_key(&irq, _RET_IP_);
  //Other itterupts are unlikely to choose our same entry_point
  int entry_point = gate_key % (POOL_SIZE - 4);
  uint8_t  *fast_pool;// = this_cpu_ptr(&irq_randomness);
  struct pt_regs    *regs = get_irq_regs();
  unsigned long   now = jiffies;
  //irq_flags contains a few bits, and every bit counts.
  cycles_t    cycles = irq_flags;
  __u32     c_high, j_high;
  __u64     ip = _RET_IP_;
  unsigned long   seed ;

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
  fast_pool[1] ^= seed >> 32;
  fast_pool[2] ^= gate_key;
  fast_pool[3] ^= gate_key >> 32;

  //_mix_pool_bytes() is great and all, but this is called a lot, we want somthing faster. 
  //A single O(1) XOR operation is the best we can get to drip the entropy back into the pool
  fast_keypool_addition(fast_pool, gate_key, 4);
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

/*
 * Getting entropy on a fresh system is a hard thing to do. 
 * So, we will start with latent_entropy, although it isn't required it doesn't hurt.
 * Then lets take addresses we know about - add them to the mix
 * Fire up the debugger, and look for reigions of memory with good data. 
 * The zero page has hardware identifieres that can be hard to guess. 
 * Then derive a key the best we can given the degraded state of the pool.
 * 
 * find_more_entropy_in_memory() is called when extract_crng_user can't be used.
 * get_random_u32() and get_random_u64() can't be used.
 *
 */
static void find_more_entropy_in_memory(int nbytes_needed)
{
  AesOfbContext   aesOfb;
  //Even if the entropy pool is all zeros - 
  //latent_entropy will give us somthing, which is the point of the plugin.
  uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
  uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
  uint8_t    *anvil;
  int        jump_point = 0;
  u64        gate_key = make_gate_key(&anvil, _RET_IP_);

  //twigs when wrapped together can become loadbearing
  //_unique_key() is not safe at this point - but it is unique enough as a seed.
  //We will use it as a jump table, to get chunks.
  //Lets allocate a chunk of memory from the heap
  //we are not setting the memory any noise here is gold
  anvil = (uint8_t *)malloc(nbytes_needed);
  for(int block_index=0; block_index < nbytes_needed; block_index+=BLOCK_SIZE){
    //Chunk it in one at a time - which will cause writes to the table.
    jump_point = _unique_key(anvil + block_index, gate_key, jump_point, BLOCK_SIZE);
  }
  
  //Gather Compile time entropy
  //  - GCC's latent_entropy on anvil, local_key and local_iv
  //  - machine code of this method (EIP), and anything near by.
  //  - machine code of whoever called us, and anything near by.
  //Copy recentally used instructions from the caller
  xor_bits(anvil, _RET_IP_, nbytes_needed, nbytes_needed, nbytes_needed);
  xor_bits(anvil, _RET_IP_ - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Copy from the instructions around us:
  xor_bits(anvil, _THIS_IP_, nbytes_needed, nbytes_needed, nbytes_needed);
  xor_bits(anvil, _THIS_IP_ - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);

  //Gather Runtime Entropy
  //  - Data from the zero page
  //  - Memory addresses from the stack and heap
  //  - Unset memory on the heap that may contain noise
  //  - Unallocated memory that maybe have used or in use
  //Copy from the zero page, contains HW IDs from the bios
  xor_bits(anvil, ZERO_PAGE, nbytes_needed, nbytes_needed, nbytes_needed);

  //Lets add as many easily accessable unknowns as we can:
  //Even without ASLR some addresses can be more difficult to guess than others.
  //With ASLR, this would be paritally feedback noise, with offsets.
  //Add any addresses that are unknown under POOL_SIZE
  //16 addresses for 64-bit is ideal, 32 should use 32 addresses to make 1024 bits.
  //Todo: use a debugger to find the 32 hardest to guess addresses.
  anvil[0] ^= (u64)&anvil;
  anvil[1] ^= (u64)_RET_IP_;
  anvil[2] ^= (u64)_THIS_IP_;
  anvil[3] ^= (u64)&gate_key;
  anvil[5] ^= (u64)jump_point;
  anvil[6] ^= (u64)&jump_point;

  //XOR untouched memory from the heap - any noise here is golden.
  xor_bits(anvil, local_iv, nbytes_needed, nbytes_needed, nbytes_needed);
  //XOR memory from the heap that we haven't allocated
  //is there a part of the bss that would be good to copy from?
  xor_bits(anvil, local_iv - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  xor_bits(anvil, local_iv + nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Copy memory from the stack that was used before our execution
  xor_bits(anvil, anvil + nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Copy memory from the stack that hasn't been used
  xor_bits(anvil, anvil - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);

  //Lets what we have now to build stronger keys
  fast_keypool_addition(anvil, gate_key + jump_point, nbytes_needed);
  //_unique_key will do its job - the IV and Key will be globally unique
  jump_point = _unique_key(local_iv, gate_key, 0, BLOCK_SIZE);
  jump_point = _unique_key(local_key, gate_key, jump_point, BLOCK_SIZE);
  //Reschedule the key so that it is more trustworthy cipher text:
  AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
  //Make the plaintext input used in key derivation distinct:
  jump_point = _unique_key(local_iv, gate_key, 0, BLOCK_SIZE);
  jump_point = _unique_key(local_key, gate_key, jump_point, BLOCK_SIZE);  
  AesOfbOutput(&aesOfb, local_iv, sizeof(local_iv));
  AesOfbOutput(&aesOfb, local_key, sizeof(local_key));
  //A block cipher is used as a KDF when we have low-entropy
  //The keys will be pure PRNG from a trusted block cipher like AES:
  AesOfbInitialiseWithKey( &aesOfb, local_key, (BLOCK_SIZE/8), local_iv );

  //Use this new block-cipher PRNG as the hammer for the anvil
  AesOfbOutput(&aesOfb, anvil, nbytes_needed);

  //We don't need fast_mix to shuffle our bits, the block cipher has done enough of this.
  fast_keypool_addition(anvil, gate_key + jump_point, nbytes_needed);
  //Things are pretty good.
  //The driver is warm, _unique_key() is reasonable.
  //Lets take the keypool for a spin:
  extract_crng_user_unlimited(anvil, nbytes_needed);

  //Add this source:
  fast_keypool_addition(anvil, gate_key, nbytes_needed);

  //gtg
  free(anvil);
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
 
    //u32 small = get_random_u32();
    //u64 mid = get_random_u64();
    //printf("%l",small);
    //printf("\n\n");
    //printf("%llu",mid);
    //printf("\n\n");

    //lets fill a request
    extract_crng_user(local_block, BLOCK_SIZE*2);
    for (int i = 0; i < BLOCK_SIZE*2; i++)
    {
            printf("%1x", local_block[i]);
    }
    printf("\n\n");
    extract_crng_user_unlimited(local_block, BLOCK_SIZE*2);
    for (int i = 0; i < BLOCK_SIZE*2; i++)
    {
            printf("%1x", local_block[i]);
    }
    return 0;
}
