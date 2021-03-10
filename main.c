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

/*

## Maths
I do like math, and if there is one part of the linux kernel that is deserving of formal verificiation it is /dev/random.  Initlaly I was egar to write mundane proofs for each operation, but I don't think this will help communicate the efficacy of these changes. I feel that I can deseribe the secrity of this system in just three proofs, which are as follows;
Reducing the operations used helps with the verification process as it is less complexity to describe.  
"Complexity is the worst enenmy of security." - Bruce Schnier. 

Proof by Observation - we see block ciphers like AES preserving confedentiality.  SSL/TLS uses AES for this purpose and it seems to be working out. 

Pigeonhole Principle - Assume one or more threads generate a new "gatekey" at the same time.  If the gatekey is generated by taking the location or address of where the key is generated, and when or a timestamp taken in clockcycles - then no two threds can fill these two properties at the same time. 

Probability Space - With a circular jumptable of 1024 possible possition bytes, the chance of a duplicate is more difficult than the 728bit AES keyspace.

Notes:
 - Circular jump table for adding and obtaining entrpy from the keypool.
 - Multiple readers/writers while maintaining NIST requirements.
 - Byte Spraying creates a field of possilbe modifications to the pool.
 - Race conditions make the pool state less predictable.
 - The 'anvil' variables are used in obtaining PRNG

*/
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


//_THIS_IP_ must be called from a macro to make it distinct.
//This process is ideal as a macro because _RET_IP_ and _THIS_IP_ will be more distinct
//If -_gatekey() was a funciton then _THIS_IP_ will be the same every time.
#ifndef __make_gatekey
  #define __make_gatekey(new_key)((u64)jiffies ^ (u64)_RET_IP_ ^ (u64)new_key ^ (u64)_THIS_IP_)
  //todo: 32bit
  //#else
  //#define _gatekey(new_key)((u32)_RET_IP_ << 32 | ((u32)&new_key ^ (u32)_THIS_IP_))|((u32)_THIS_IP_ << 32 | (u32)&new_key);
  //#endif
/*
    anvil ^= ((u32)consumer_ip << 32 | ((u32)&origin_address ^ (u32)_THIS_IP_));
    anvil ^= ((u32)&origin_address << 32 | (u32)&anvil);
*/
#endif

static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes);
static void crng_reseed(struct crng_state *crng, struct entropy_store *r);
void _unique_key(u64 uu_key[], u64 gatekey, int nbytes);

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
void  xor_bits( uint8_t dest[], uint8_t source[], int source_len, u64 bit_offset, u64 byte_length)
{
  //The start byte to start the copy
  int start_byte = (bit_offset/32) % byte_length;
  int pos = bit_offset%32;
  //The start bit within the first byte
  for(int k = 0; k < byte_length; k++)
  {
    //Treat the source as a circular buffer.          
    if(start_byte + k > source_len)
    {
       start_byte = 0;
      //Protective - this won't happen
      if(k > source_len)
      {
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

/* Add uniqeness to the keypool
 *
 * Uniqeness is not only in value, but also position.
 *
 * _add_unique() shuffles in individual bytes into a larger pool.
 * We want to spray bytes across the pool evenly to create a filed of possilbites
 * With each jump more unkown is introduced to this field.
 * With this shuffling strategy an attacker is forced to work harder, 
 * and it is O(n) to copy bytes using a jump table or with a linear copy.
 * 
 * More than one thread maybe using _add_unique() on the same global buffer.
 * There is a 1/POOL_SIZE chance of a collision and a loss of a single bit,
 * if we copied over the new entropy linearly, there is a 1/POOL_SIZE chance 
 * we would lose all bytes. Spreading out the writes helps avoid this problem.
 * At the time of this writing POOL_SIZE is 1kb, and 1kb/per-tick of bandwidth is just fine.
 *
 * This shuffling stratigy was built to support the volume of writes created by handle_irq_event_percpu()
 * New CPUs can have 64 cores, adding more locks doesn't scale - 
 * However, increasing POOL_SIZE linearly decreases loss of entropy due to write collisions. 
 * If write collisions from handle_irq_event_percpu() goes up, we can make POOL_SIZE larger.
 */
void _add_unique(uint8_t keypool[], int keypool_size, u64 gatekey, uint8_t unique[], int unique_size, int nbytes)
{
  u64 anvil_addr = gatekey % keypool_size;
  u64 next_jump = 0;
  int read_index = 0;
  //Copy bytes with a jump table - O(n)
  for(int i = 0; i < nbytes;i++)
  {
    //Make our read source circular
    read_index++;
    if(read_index > unique_size)
    {
      read_index = 0;
    }
    //Pick a random point to jump to - O(1)
    //Add in the gatekey so this jump path is distict
    next_jump = ((u64)keypool[anvil_addr] + gatekey) % keypool_size;

    //With a strike of the anvil - a new byte has been added to the pool
    keypool[anvil_addr] ^= unique[i];
    //Find the next place to strike
    anvil_addr = next_jump;
  }
  next_jump = 0;
  anvil_addr = 0;
}

/*
 * Obtain a uniqeness from the keypool
 *
 * To do this, no to threads can follow the same jump path.
 *
 * A lock isn't needed because no two threads will be able to follow the same path.
 * We assume this holds true due the pidgen hole pricple behind the gatekey generation.
 * 
 * This method is linear O(n), and we want to force our attacker into an exponet.
 * KEYPOOL_SIZE * bites is possilbe entry points (1024*8)
 * We have four combinations of these; (1024*8)^4
 *  - making a total of 2^52 possible combinations for any given keypool.
 *
 * The gatekey and state of the keypool is used to derive 4 jump distinct points.
 * It is like taking two MRI scans of a sand castle, then putting them in a XOR killidiscope.
 *
 * Constrants:
 *   Each of the four layers must be unique, to prevent a^a=0
 *   Make sure our jump path to choose layers is distinct from other parallell invocations
 *   To prevent future repeats of a jump path we overwite our jump index
 * 
 */
void _get_unique(uint8_t keypool[], int keypool_size, u64 gatekey, uint8_t unique[], int nbytes)
{
  //The caller has the option of stacking PRNG
  //Lets use the keypool with a jump table -
  //this jumptable pattern follows a similar pattern to the AES counterpart.
  uint8_t anvil[POOL_SIZE] __latent_entropy;
  u64 first_layer = keypool[gatekey % keypool_size];
  u64 second_layer = 0;
  u64 third_layer = 0;
  u64 fourth_layer = 0;
  int upper_bound = 0;

  //die();
  //We can't produce any more than POOL_SIZE bytes per position
  //Invocations should only use one interation of the loop,
  //But we can return more to be future-proof and protective.
  for(int chunk = 0; nbytes > 0; nbytes-=chunk)
  {
    //After POOL_SIZE bytes we need four new points
    chunk = __min(POOL_SIZE, nbytes);
    int current_pos = nbytes - chunk;

    //We need a unique value from a global buffer
    second_layer = (u64)keypool[first_layer % POOL_SIZE];
    //Make our jump path unique to this call:
    second_layer ^= gatekey;
    //If we choose the same point then we XOR the same values.
    //Fall to either side, don't prefer one side.
    if((first_layer % POOL_SIZE_BITS) == (second_layer % POOL_SIZE_BITS))
    {
      //flip a coin, move a layer
      first_layer += (second_layer % 2) ? 1 : -1;
    }

    //Get our first layer in place
    xor_bits(unique + current_pos, keypool, keypool_size, first_layer, chunk);
    //Add our random 2nd layer to make (noise ^ noise)
    xor_bits(unique + current_pos, keypool, keypool_size, second_layer, chunk);

    //clean our entry point so this first and second layer can never be re-used.
    //the first 64bits of unique are *removed* from the first layer of the keypool.
    keypool[first_layer % POOL_SIZE] ^= (u64)unique;

    //shift a u64 number of bits forward.
    first_layer += 8;
  }

  //Cover our tracks
  first_layer = 0;
  second_layer = 0;
  third_layer = 0;
  fourth_layer = 0;
  gatekey = 0;
}


/*
 * The goal here is to be fast
 * the user needs less 1 block, they only need two words.
 * Lets fill the request as quickly as we can.
 * we add __latent_entropy, because we are called early in execution
 * it is good to have all the sources we can get.
 */
u64 get_random_u64(void)
{
  u64 anvil __latent_entropy;
  _unique_key((u64 *)&anvil, __make_gatekey(&anvil), sizeof(anvil));
  return anvil;
}

/* 
 * we want to return just one byte as quickly as possilbe. 
 * not use in using a 128 or 256-bit cypher for 32 bits
 * __make_gatekey is plenty unique for this purpose
 * get_random_u32 is for intenal users
 */
u32 get_random_u32(void)
{
  u32 anvil __latent_entropy;
  _unique_key((u32 *)&anvil, __make_gatekey(&anvil), sizeof(anvil));
  return anvil;
}

/*
 * There are many times when we need another opinion. 
 * Ideally that would come from another source, such as arch_get_random_seed_long()
 * When we don't have a arch_get_random_seed_long, then we'll use ourselves as a source.
 * 
 * Failure is not an option - and this output is untrusted.
 * The output should be XOR'ed with a random value from a different source.
 */
u64 _alternate_rand()
{
  //Need a source that isn't GCC's latententropy or time.
  u64 anvil = 0;
  //Try every source we know of, taken from random.c:
  if(!arch_get_random_seed_long(&anvil))
  {
      if(!arch_get_random_long(&anvil))
      {
         anvil = random_get_entropy();
      }
  }
  //anvil might still be zero - sure this could have been an unlucky roll
  // - but it also could be hardware letting us down, we can't tell the differnece.
  //Worst case, we are missing everything above
  if(!anvil)
  {
    //If this isn't populated we'll get a compiler error.
    anvil = __make_gatekey(anvil);
  }
  return anvil;
}

/*
 * The goal of _unique_key is to return universally-unique key material
 * that an attacker cannot guess. 
 * 
 * The addition of identifing information (gatekey) and timestamp 
 * - is taken from UUID4 creation to ensure universal unquness.
*/
void _unique_key(u64 uu_key[], u64 gatekey, int nbytes)
{
  u64 anvil __latent_entropy;
  //_alternate_rand() isn't trusted, so we XOR it with a the __latent_entropy compile-time secret
  anvil ^= _alternate_rand();

  //Pull in layers of PRNG to get a unique read
  _get_unique(primary_crng.state, POOL_SIZE, gatekey, uu_key, nbytes);

  //by adding uniqness from our local state we have yet another reason why the return value is distinct
  _add_unique(uu_key, nbytes, gatekey, &gatekey, sizeof(gatekey), sizeof(gatekey));
  //make more unique, add a hardware source:
  _add_unique(uu_key, nbytes, gatekey, &anvil, sizeof(anvil), sizeof(anvil));

  //clean and return
  gatekey = 0;
  anvil = 0;
}

/*
 * Public functon to provide CRNG
 *
 *  - Generate some very hard to guess key material
 *  - Use the fastest cryptographic primitive aviailble
 *  - Return CRNG back to the user as quckly as we can
 *  - Cleanup so we can do this all over again
 * 
 * This is where users get their entropy from the random.c 
 * device driver (i.e. reading /dev/random)
 */
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes){
    //get_random_u32() and get_random_u64() are faster
    //If we only need a few bytes these two are the best source.
    if(nbytes <= 0){
      return nbytes;
    }else if(nbytes < BLOCK_SIZE){
      uint8_t    anvil[BLOCK_SIZE] __latent_entropy;
      //Get upto one block of good CRNG:
      _unique_key(anvil, __make_gatekey(anvil), BLOCK_SIZE);
      //Copy into user space
      memcpy(__user_buf, anvil, nbytes);
      //cover our tracks
      memzero_explicit(anvil, BLOCK_SIZE);
    }else{
      //Ok, we need somthing bigger, time for OFB.
      uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
      uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
      AesOfbContext   aesOfb; 
      size_t amountLeft = nbytes;
      int chunk;
      //For key scheduling purposes, the entropy pool acts as a kind of twist table.
      //The pool is circular, so our starting point can be the last element in the array. 
      _unique_key(local_iv, __make_gatekey(local_iv), BLOCK_SIZE);

      //Select the key:
      _unique_key(local_key, __make_gatekey(local_key), BLOCK_SIZE);

      //Generate one block of PRNG
      AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv );

      //Zero out memeory to prevent backtracking
      memzero_explicit(local_iv, sizeof(local_iv));
      memzero_explicit(local_key, sizeof(local_iv));
      
      //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
      AesOfbOutput(&aesOfb, __user_buf, nbytes);
    }
    //Cleanup complete 
    //at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
}

// This is the /dev/urandom variant.
// it is simlar to the algorithm above, but more time is spent procuring stronger key mateiral.
// the user is willing to wait, so we'll do our very best.
// when this method completes, the keypool as a whole is better off, as it will be re-scheduled.
 /*
 * Be an _unlimited_ random source
 * Speed is not an issue
 * Provide the very best source possilbe
 * 
 * Rolling accumulator keys
 * Key, IV, and Image accumulate entropy with each operation
 * They are never overwritten, only XOR'ed with the previous value
 */
static ssize_t extract_crng_user_unlimited(uint8_t *__user_buf, size_t nbytes)
{
    //__latent_entropy is better than zeros
    uint8_t   key_accumulator[BLOCK_SIZE] __latent_entropy;
    uint8_t   hardned_key[BLOCK_SIZE] __latent_entropy;
    uint8_t   hardend_iv[BLOCK_SIZE] __latent_entropy;
    uint8_t   hardend_image[BLOCK_SIZE] __latent_entropy;    
    AesOfbContext   aesOfb;
    size_t amountLeft = nbytes;
    int chunk;

    if(nbytes <= 0){
      return nbytes;
    }

    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array.
    _unique_key(hardned_key, __make_gatekey(hardned_key), BLOCK_SIZE);
    _unique_key(hardend_iv, __make_gatekey(hardend_iv), BLOCK_SIZE);
    //Encrypting noise is harder to guess than zeros
    _unique_key(hardend_image, __make_gatekey(hardend_image), BLOCK_SIZE);

    //The key, IV and Image will tumble for as long as they need, and copy out PRNG to the user. 
    //At no point will a Key, or IV or Image ever be-reused.
    while( amountLeft > 0 )
    {
        chunk = __min(amountLeft, BLOCK_SIZE );

        //Grab a new BLOCK_SIZE and XOR it with the previous state.
        _unique_key(key_accumulator, __make_gatekey(key_accumulator), BLOCK_SIZE);
        //Add this new round of entropy to our keys
        _add_unique(hardned_key, BLOCK_SIZE, __make_gatekey(hardned_key), key_accumulator, BLOCK_SIZE, BLOCK_SIZE);

        //Generate one block of PRNG
        AesOfbInitialiseWithKey(&aesOfb, hardned_key, (BLOCK_SIZE/8), hardend_iv);
        //Image countinly encrypted in place, the cyphertext rolls over so plaintext simularity is not a concern.
        AesOfbOutput(&aesOfb, hardend_image, chunk);
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        memcpy(__user_buf + (nbytes - amountLeft), hardend_image, chunk);
        amountLeft -= chunk;

        //All previous used Key+IV pairs have affected the resulting hardend_image
        //hardend_image will be universally unique for each interation.

        //Do we need another bock?
        if(amountLeft > 0)
        {
          //At the end of the loop we get:
          //The cipher text from this round is in local_image, which in the input for the next round
          //The IV is a PRNG feedback as per the OFB spec - this is consistant
          //A new secret key is re-chosen each round, the new IV is used to choose the new key.
          //Using an IV as an index insures this instance has a key that is unkown to others - at no extra cost O(1).
           //Todo capture IV and use it.
           AesOfbOutput(&aesOfb, hardend_iv, chunk);
          //This is the resulting IV unused from AES-OFB, intened to be used in the next round:
          //_add_unique(hardend_iv, BLOCK_SIZE, __make_gatekey(hardend_iv), aesOfb.CurrentCipherBlock, BLOCK_SIZE, BLOCK_SIZE);
        }
     }
    //Cover our tracks.
    memzero_explicit(key_accumulator, sizeof(key_accumulator));
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
  //Globally unique gatekey
  uint64_t gatekey = __make_gatekey(&irq);
  //Other itterupts are unlikely to choose our same entry_point
  int entry_point = gatekey % (POOL_SIZE - 4);
  u64  fast_pool[4];// = this_cpu_ptr(&irq_randomness);
  struct pt_regs    *regs = get_irq_regs();
  unsigned long   now = jiffies;
  //irq_flags contains a few bits, and every bit counts.
  cycles_t    cycles = irq_flags;
  __u32     c_high, j_high;
  __u64     ip = _RET_IP_;
  unsigned long   seed __latent_entropy;

  //This code is adapted from the old random.c - all O(1) operations
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
  seed ^= _alternate_rand();
  
  //Seed is 64 bits, so lets squeeze ever bit out of that.
  fast_pool[0] ^= seed;
  fast_pool[1] ^= seed >> 32;
  fast_pool[2] ^= gatekey;
  fast_pool[3] ^= gatekey >> 32;

  //_mix_pool_bytes() is great and all, but this is called a lot, we want somthing faster. 
  //A single O(1) XOR operation is the best we can get to drip the entropy back into the pool
  _add_unique(primary_crng.state, POOL_SIZE, gatekey, fast_pool, 32, 32);
}

static void crng_reseed(struct crng_state *crng, struct entropy_store *r)
{
  AesOfbContext   aesOfb; 
  unsigned long flags;
  int crng_init;
  int   i, num;
  u8         fresh_prng[POOL_SIZE];
  uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
  uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
  union {
    __u8  block[BLOCK_SIZE];
    __u32 key[8];
  } buf;

  // fetch an IV in the current state.
  _unique_key(local_iv, __make_gatekey(local_iv), BLOCK_SIZE);
  _unique_key(local_key, __make_gatekey(local_key), BLOCK_SIZE);

  //Output of extract_crng_user() will XOR with the current primary_crng.state
  extract_crng_user(primary_crng.state, sizeof(primary_crng.state));
  //encrypt the entire entropy pool with the new key:
  AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv);
  //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
  AesOfbOutput(&aesOfb, primary_crng.state, POOL_SIZE); 

  //We bathe in the purest PRNG
  extract_crng_user_unlimited(fresh_prng, POOL_SIZE);

  //Cleanup to prevent leakage of secrets:
  memzero_explicit(&buf, sizeof(buf));
  memzero_explicit(&local_iv, sizeof(local_iv));
  memzero_explicit(&local_key, sizeof(local_key));
  memzero_explicit(fresh_prng, POOL_SIZE);
  primary_crng.init_time = jiffies;
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
static void find_more_entropy_in_memory(struct crng_state *crng, int nbytes_needed)
{
  AesOfbContext   aesOfb;
  //Even if the entropy pool is all zeros - 
  //latent_entropy will give us somthing, which is the point of the plugin.
  uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
  uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
  uint8_t    *anvil;
  u64        gatekey;
  gatekey  = __make_gatekey(&anvil);

  //a place to forge some entrpy
  anvil = (uint8_t *)malloc(nbytes_needed);

  //Lets add as many easily accessable unknowns as we can:
  //Even without ASLR some addresses can be more difficult to guess than others.
  //With ASLR, this would be paritally feedback noise, with offsets.
  //Add any addresses that are unknown under POOL_SIZE
  //16 addresses for 64-bit is ideal, 32 should use 32 addresses to make 1024 bits.
  //Todo: use a debugger to find the 32 hardest to guess addresses.
  void *points_of_interest[] = {
      ZERO_PAGE,
      _RET_IP_,
      _THIS_IP_,
      anvil,
      gatekey
  };

  //Gather Runtime Entropy
  //  - Data from the zero page
  //  - Memory addresses from the stack and heap and 'anvil' points to the heap.
  //  - Unset memory on the heap that may contain noise
  //  - Unallocated memory that maybe have used or in use
  //Copy from the zero page, contains HW IDs from the bios
  for(int index = 0; index < sizeof(points_of_interest); index++){
    void *readPoint = points_of_interest[index];
    // Grab the uniqeness of this address:
    _add_unique(crng, POOL_SIZE, gatekey, &readPoint, sizeof(readPoint), sizeof(readPoint));
    // Pull in uniqueness from this page in memory:
    // Todo - read the values at this address - we want the contents of the zero page:
    // _add_unique(crng, POOL_SIZE, gatekey, readPoint, nbytes_needed, nbytes_needed);
  }

  //twigs when wrapped together can become loadbearing
  //a samurai sword has many layers of steel.
  //_unique_key() might not be not safe at this point  
  // - but it is unique enough as a seed.
  _unique_key(anvil, gatekey, nbytes_needed);
  _add_unique(crng, POOL_SIZE, gatekey, anvil, nbytes_needed, nbytes_needed);

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

    //let's assume the entrpy pool is the same state as a running linux kernel
    //start empty
    memset(local_block, 0, sizeof local_block); 

    //Assume this is the normal startup procedure from the kernel.
    load_file(runtime_entropy, POOL_SIZE);    
    find_more_entropy_in_memory(runtime_entropy, POOL_SIZE);
    //Start with noise in the pool for the jump table.
    //This will ensure that _unique_key() doesn't depend on __latent_entropy
    crng_reseed(runtime_entropy, runtime_entropy);

    //u64 gatekey;
    u32 small = get_random_u32();
    printf("small:%lu", small);
    printf("\n\n"); 
    //exit();
    u64 mid = get_random_u64();
    printf("mid:%lu", mid);
    printf("%llu", mid);
    printf("\n\n");

    //printf("gatekey:%llu",gatekey);
    printf("\n\n");
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
