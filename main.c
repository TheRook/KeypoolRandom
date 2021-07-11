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

Sheaf - Implamented by a circular jumptable of 2^1024 possible ring-functions accessed by a gatekey.  

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
// knockout.h is linux kernel scaffolding
#include "aes.h"
#include "knockout.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define KEYPOOL_SIZE             1024
#define BLOCK_SIZE              256
#define BLOCK_SIZE_BITS         BLOCK_SIZE * 8
#define POOL_SIZE               BLOCK_SIZE * 4
#define POOL_SIZE_BITS          BLOCK_SIZE * 8


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Global runtime entropy
uint8_t runtime_entropy[POOL_SIZE] __latent_entropy;
static __u32 input_pool_data[INPUT_POOL_WORDS] __latent_entropy;
static __u32 blocking_pool_data[OUTPUT_POOL_WORDS] __latent_entropy;

static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes);
static void crng_reseed(uint8_t *crng_pool, size_t nbytes);
void _unique_iid(u64 uu_key[], u64 gatekey, size_t nbytes, int rotate);
u64 _alternate_rand();
//_THIS_IP_ must be called from a macro to make it distinct.
//This process is ideal as a macro because _RET_IP_ and _THIS_IP_ will be more distinct
//If -_gatekey() was a funciton then _THIS_IP_ will be the same every time.
#ifndef __make_gatekey
  #define __make_gatekey(new_key)((u64)jiffies ^ (u64)_RET_IP_ ^ (u64)new_key ^ (u64)_THIS_IP_ ^ _alternate_rand())
  //todo: 32bit
  //#else
  //#define _gatekey(new_key)((u32)_RET_IP_ << 32 | ((u32)&new_key ^ (u32)_THIS_IP_))|((u32)_THIS_IP_ << 32 | (u32)&new_key);
  //#endif
#endif

// Rotate bits
// Bits are not lost so there isn't loss of entropy.
uint64_t rotl64 ( uint64_t x, int8_t r )
{
  r = r % 64;
  return (x << r) | (x >> (64 - r));
}

// Restore the pool from disk.
int load_file(uint8_t *dest, size_t len)
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

/* Add two buffers to generate uncertainty
 *
 * _add_unique() will spray bytes across the pool evenly to create a filed of possilbites
 * With each jump more uncertainty is introduced to this field.
 * With this shuffling strategy an attacker is forced to work harder, 
 * and it is O(n) to copy bytes using a jump table or with a linear copy.
 *
 * This shuffling stratigy was built to support the volume of writes created by handle_irq_event_percpu()
 * There is no lock over the keypool, and all writes are done via atomic XOR operations.
 * Even if a write was lost do to a race condition, it would be difficult to determine what was kept and was wasn't.
 * Any effect of a race condition would make it even harder to reconstruct the keypool state.
 * 
 */
void _add_unique(uint8_t keypool[], int keypool_size, u64 gatekey, uint8_t unique[], int unique_size, int nbytes)
{
  // Write in the first byte that is read by _get_unique() which is in 64 bits.
  int next_jump = (gatekey * 8) % (keypool_size / 8);
  // Copy bytes with a jump table - O(n)
  for(int step = 0; step < nbytes; step++)
  {
    // Check if there is somthing to add.
    if(unique[step] != 0){
      // Every byte within keypool_size can be written to at the same time without loosing a write.
      keypool[next_jump] ^= unique[step];
      // Save off the jump address before we change it. 
      next_jump ^= keypool[next_jump];
      // Circular buffer
      next_jump = keypool_size % keypool_size;
    }
  }
  //Leave no trace
  gatekey = 0;
  next_jump = 0;
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
void _get_unique(uint8_t *keypool, int keypool_size, u64 gatekey, uint8_t *unique, size_t nbytes)
{
  uint64_t *keyspace = (uint64_t *) &keypool;
  uint64_t *product = (uint64_t *) &unique;
  // We extract out 64bits at a time for performence.
  int64_t keypool_size_64 = keypool_size / 8;
  uint8_t gate_position = (uint8_t) gatekey % keypool_size_64;
  uint8_t  jump_offset;
  // We need to seed the process with our first jump location
  product[0] ^= gatekey;
  // A prime is used to maximize the number of reads without repeat
  jump_offset = keypool_primes[product[1] % sizeof(keypool_primes)];
  // Pull 64bits at a time out of the ring function
  for(size_t step = 0; step < nbytes/8; step++)
  {
    // Pull the next 64bits from the entropy source:
    product[step] ^= keyspace[gate_position];
    // A shift rotate will make our reads less predictable without loosing entropy
    // Here we rotate by an uncertin degree, making our local state more unique
    product[step] = rotl64(product[step], unique[step]%64);    
    // Pick another 64bit chunk that is somewhere else in the pool and doesn't overlap
    gate_position = (gate_position + jump_offset) % keypool_size_64;
    product[step] ^= keyspace[gate_position];
    // Assume that 'keyspace' is shared, so we add a local rotation
    product[step] = rotl64(product[step], unique[step+1]%64);
    // Find another point to read from that is distinct.
    gate_position = (gate_position + jump_offset) % keypool_size_64;
  }
}

/*
 * The goal of _unique_aes is to produce an unpredictable I.I.D. stream
 * _get_unique() is meant to be as difficult to predict as possilbe but,
 * it is not fully I.I.D. - and it doesn't need to be.
 * 
*/
void _unique_aes(u8 uu_key[], u64 gatekey, size_t nbytes, int rotate)
{
  struct AES_ctx ctx;
  uint8_t aes_key_material[BLOCK_SIZE * 3] __latent_entropy;
  uint8_t *aes_key = aes_key_material;
  uint8_t *aes_iv = aes_key_material + BLOCK_SIZE;
  uint8_t *aes_block = aes_key_material + BLOCK_SIZE * 2;
  uint64_t *aes_block_rotate = (uint64_t *)aes_block;
  uint64_t *jump_rotate = (uint64_t *) &runtime_entropy;
  size_t jump_rotate_size = KEYPOOL_SIZE / 8;
  size_t amount_left = nbytes;
  size_t chunk = 0;
  // Get a new key, iv and preimage from the entropy pool:
  _get_unique(runtime_entropy, KEYPOOL_SIZE, gatekey, aes_key_material, sizeof(aes_key_material));
  // Cover our tracks
  // Make sure this gatekey + entry location can never be reused:
  // No two accessors can generate the same gatekey so this is threadsafe.
  _add_unique(runtime_entropy, POOL_SIZE, gatekey, aes_block_rotate, sizeof(gatekey), sizeof(gatekey));
  // Pull 64bits at a time out of the ring function
  while( amount_left > 0 )
  {
    // account for sizes that are not evenly divisable by BLOCK_SIZE.
    chunk = __min(amount_left, BLOCK_SIZE);
    // Populate our cipher struct
    AES_init_ctx_iv(&ctx, aes_key, aes_iv);
    // Encrypt one block with AES-CBC-128:
    AES_CBC_encrypt_buffer(&ctx, aes_block, BLOCK_SIZE);
    // Copy the first 64bits to the user:
    memcpy(uu_key, aes_block, chunk);
    amount_left -= BLOCK_SIZE;
    if(amount_left > 0)
    {
      // move our copy destination
      uu_key += chunk;
      if(rotate)
      {
        // Rotate the key material with the output so that similar keys are never reused:
        _add_unique(aes_key_material, BLOCK_SIZE*3, gatekey, aes_block, BLOCK_SIZE, BLOCK_SIZE);
      }
      // The ciphertext from the previous call to aes() is the plaintext for the next invocation.
    }
  }
  // Cleanup the secrets used
  memzero_explicit(&aes_key_material, BLOCK_SIZE*3);
  gatekey ^= gatekey;
}

/*
 * The goal is to produce a very secure source of I.I.D.
 * (Independent and identically distributed)
 * This is a wrapper to dispatch to whatever primitive is best
 */
void _unique_iid(u64 uu_key[], u64 gatekey, size_t nbytes, int rotate)
{
  // AES-NI should be faster than sha1 on platforms that support it.
  // todo - _unique_sha1() and _unique_other() for flexabilty.
  return _unique_aes(uu_key,gatekey,nbytes,rotate);
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
  u64 anvil;
  _unique_iid((u64 *)&anvil, __make_gatekey(&anvil), sizeof(anvil), 0);
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
  u32 anvil;
  _unique_iid((u32 *)&anvil, __make_gatekey(&anvil), sizeof(anvil), 0);
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
  // anvil might still be zero -  
  // We can't tell the differnece between a zero-roll and a hardware error code.
  // Worst case, we are missing everything above
  if(anvil == 0)
  {
    // We cannot fail, in this case we pull from the pool
    // This output is used to make a gatekey, so time is used
    // No two calls can use the exact same jiffies + &anvil due to the pidgehole priciple
    // todo: 32bit
    u64 alternate_gatekey __latent_entropy;
    alternate_gatekey ^= (u64)jiffies ^ (u64)&anvil;
    _unique_iid(&anvil, alternate_gatekey, sizeof(anvil), 0);
    // 'anvil' is a small jump table entropy pool that we can further enrich
    _add_unique(&anvil, sizeof(anvil), alternate_gatekey, &alternate_gatekey, sizeof(alternate_gatekey), sizeof(alternate_gatekey));
    // cleanup
    alternate_gatekey = 0;
  }
  return anvil;
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
    //If we only need a few bytes these two are the best source.
    if(nbytes <= 0){
      return nbytes;
    } else {
      // Fill the request - no rotate
      _unique_iid(__user_buf, __make_gatekey(__user_buf), nbytes, 0);  
    }     
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
    //If we only need a few bytes these two are the best source.
    if(nbytes <= 0){
      return nbytes;
    } else {
      // Fill the request - rotate key mateiral:
      _unique_iid(__user_buf, __make_gatekey(__user_buf), nbytes, 1);  
    }     
    //at this point it should not be possilbe to re-create any part of the PRNG stream used.
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
  uint64_t gatekey __latent_entropy;
  u64  fast_pool[5] __latent_entropy;
  struct pt_regs    *regs = get_irq_regs();
  //irq_flags contains a few bits, and every bit counts.
  cycles_t    cycles = irq_flags;
  __u32     c_high, j_high;
  __u64     ip = _RET_IP_;

  //This code is adapted from the old random.c - all O(1) operations
  //The interrupt + time gives us 4 bytes.
  if (cycles == 0)
    cycles = get_reg(fast_pool, regs);
  c_high = (sizeof(cycles) > 4) ? cycles >> 32 : 0;
  j_high = (sizeof(jiffies) > 4) ? jiffies >> 32 : 0;
  fast_pool[0] ^= cycles ^ j_high ^ irq;
  fast_pool[1] ^= jiffies ^ c_high;
  fast_pool[2] ^= ip;
  fast_pool[3] ^= (sizeof(ip) > 4) ? ip >> 32 :
    get_reg(fast_pool, regs);

  // A gatekey will have some hardware randomness when available
  // It will be XOR'ed with __latent_entropy to prevent outsider control
  gatekey ^= __make_gatekey(&irq);
  // Add this unique value to the pool
  fast_pool[4] ^= gatekey;
  //A single O(1) XOR operation is the best we can get to drip the entropy back into the pool
  _add_unique(runtime_entropy, POOL_SIZE, gatekey, fast_pool, sizeof(fast_pool), sizeof(fast_pool));

  //Cleanup
  gatekey = 0;
}

static void crng_reseed(uint8_t *crng_pool, size_t nbytes)
{
  // This maybe when the pool is empty, lets get a small amount from letant entropy:
  uint64_t gatekey __latent_entropy;
  gatekey ^= __make_gatekey(&gatekey);
  uint8_t    streached_prng[POOL_SIZE];

  // Get a contianer of noise
  _unique_iid(streached_prng, gatekey, POOL_SIZE, 1);

  // re-seed with the current output, deleting the old state
  extract_crng_user(crng_pool, nbytes);

  // Add the noise obtained from a pool that no longer exists, the left washes the right.
  // Each byte is written using a jump table so its final path is unkown
  _add_unique(crng_pool, POOL_SIZE, gatekey, streached_prng, POOL_SIZE, POOL_SIZE);
  
  //cleanup
  gatekey = 0;
  memzero_explicit(&streached_prng, POOL_SIZE);
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
static void find_more_entropy_in_memory(uint8_t *crng_pool, int nbytes_needed)
{
  uint8_t    *anvil;
  // This is early in boot, __latent_entropy is helpful
  u64        gatekey __latent_entropy;
  gatekey  ^= __make_gatekey(&anvil);

  //a place to forge some entrpy
  anvil = (uint8_t *)malloc(nbytes_needed);

  //Lets add as many easily accessable unknowns as we can:
  //Even without ASLR some addresses can be more difficult to guess than others.
  //With ASLR, this would be paritally feedback noise, with offsets.
  //Add any addresses that are unknown under POOL_SIZE
  //16 addresses for 64-bit is ideal, 32 should use 32 addresses to make 1024 bits.
  //Todo: use a debugger to find the 32 hardest to guess addresses.
  void *points_of_interest[] = {
      //ZERO_PAGE,
      //_RET_IP_,
      //_THIS_IP_,
      //anvil,
      //gatekey
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
    _add_unique(crng_pool, POOL_SIZE, gatekey, &readPoint, sizeof(readPoint), sizeof(readPoint));
    // Pull in uniqueness from this page in memory:
    // Todo - read the values at this address - we want the contents of the zero page:
    //_add_unique(crng_pool, POOL_SIZE, gatekey, readPoint, nbytes_needed, nbytes_needed);
  }

  //twigs when wrapped together can become loadbearing
  //a samurai sword has many layers of steel.
  //_unique_iid() might not be not safe at this point  
  // - but it is unique enough as a seed.
  _unique_iid(anvil, gatekey, nbytes_needed, 1);
  _add_unique(crng_pool, POOL_SIZE, gatekey, anvil, nbytes_needed, nbytes_needed);
  
  //Clean up our tracks so another process cannot see our source material
  memzero_explicit(anvil, nbytes_needed);
  gatekey = 0;
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
  return extract_crng_user(buf+*ppos, nbytes-*ppos);
}

static ssize_t
urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
  //This is a non-blocking device so we are not going to wait for the pool to fill. 
  //We will respect the users wishes, and spend time to produce the best output.
  return extract_crng_user_unlimited(buf+*ppos, nbytes-*ppos);
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
    uint8_t        local_block[BLOCK_SIZE];
    uint32_t       large_block[300000];
    FILE *out_test;
    FILE *bin_test;
    //let's assume the entrpy pool is the same state as a running linux kernel
    //start empty
    memset(local_block, 0, sizeof(local_block)); 

    //Simulated start of execution:
    //Assume this is the normal startup procedure from the kernel.
    load_file(runtime_entropy, POOL_SIZE);    
    //find_more_entropy_in_memory(runtime_entropy, POOL_SIZE);
    //Start with noise in the pool for the jump table.
    //This will ensure that _unique_iid() doesn't depend on __latent_entropy
    crng_reseed(runtime_entropy, sizeof(runtime_entropy));
    add_interrupt_randomness(1, 1);
  
    //u64 gatekey;
    u32 small = get_random_u32();
    printf("small:%lu", small);
    printf("\n\n"); 
    //exit();
    u64 mid = get_random_u64();
    printf("mid:%lu", mid);
    printf("%llu", mid);
    printf("\n\n");

    printf("\n\n");
    //lets fill a request
    extract_crng_user(local_block, BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        printf("%1x", local_block[i]);
    }
    printf("\n\n");
    extract_crng_user(large_block, sizeof(large_block));
    
    out_test = fopen("output.die","w");
    bin_test = fopen("output.bin","wb");
    fwrite(large_block,sizeof(large_block),1,bin_test);
    
    fprintf(out_test, "%s", "#\n#\n#\ntype: d\ncount: 1000\nnumbit: 32\n");
    for(int x=0;x < 300000; x++){
      fprintf(out_test, "%u\n", large_block[x]);
    }
    printf("wrote to output.bin\n\n");
    return 0;
}
