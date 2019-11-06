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


//todo covert __make_gatekey() into macro... 
//_THIS_IP_ must be called from a macro to make it distinct.
//A gate key works much better as macro because _RET_IP_ and _THIS_IP_ will be more distinct
//If _gatekey() was a funciton then _THIS_IP_ will be the same every time.
#ifndef __make_gatekey
<<<<<<< HEAD
  #define __make_gatekey(new_key)((u64)jiffies ^ (u64)_RET_IP_ ^ (u64)new_key ^ (u64)_THIS_IP_)
=======
  #define __make_gatekey(new_key)((u64)jiffies ^ (u64)_RET_IP_ ^ (u64)&new_key ^ (u64)_THIS_IP_)
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  //#else
  //#define _gatekey(new_key)((u32)_RET_IP_ << 32 | ((u32)&new_key ^ (u32)_THIS_IP_))|((u32)_THIS_IP_ << 32 | (u32)&new_key);
  //#endif
#endif
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes);
static void crng_reseed(struct crng_state *crng, struct entropy_store *r);
<<<<<<< HEAD
void _unique_key(u64 uu_key[], u64 gatekey, int nbytes);
=======
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

/* 
 * A gatekey ID must be unique no matter how many threads invoke it at the same time.
 * To do this, we capture the 'who', 'what' 'when' and 'where' of the request into one value
 * Due to the pidgen-hole pirciple any caller who fills these requiremnets, must except to get the same result.
 * If the caller is the same person and getting a gatekey id at the same time 
 * - then they should expect to be identified in the same way, that what the device does.
 *
 */
u64 make_gatekey(char *origin_address, long consumer_ip)
{
  u64 anvil;

  //we have an address on the stack of where the data is going (origin_address)
  //we have the instruciton pointer of who invoked the device driver (consumer_ip)
  //We have our the 'jiffies' which is when the gatekey was created.
  //We have our stack pointer which is what we are using to generate the gatekey. 
  //When combining the; what, who, when, where we have a globally unique u64.

  //User input is combined with the entropy pool state to derive what key material is used for this gatekey.
  //The return address and current insturciton pointer are _RET_IP_ and _THIS_IP_ come from kernel.h:
  //https://elixir.bootlin.com/linux/v3.0/source/include/linux/kernel.h#L80
  //_THIS_IP_ is always going to be the same because &make_gatekey() is in a static location in memory

  //Is this larger than 32 bit?
  if(sizeof(&origin_address) > 4)
  {
    //all 64 bit values adding uniquness to the anvil.
    anvil ^= (u64)consumer_ip ^ (u64)&origin_address ^ (u64)&anvil;
  }
  else
  {
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

  //A globally unique (maybe universally uniqe) gatekey id has been minted.
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
<<<<<<< HEAD
 * we add __latent_entropy, because we are called early in execution
 * it is good to have all the sources we can get.
 */
u64 get_random_u64(void)
{
  u64 anvil __latent_entropy;
  u64 gatekey = __make_gatekey(&anvil);
  _unique_key((u64 *)&anvil, gatekey, sizeof(anvil));
=======
 */

u64 get_random_u64(void)
{
  u64 anvil;
  extract_crng_user(&anvil, sizeof(anvil));
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  return anvil;
}

/* 
 * we want to return just one byte as quickly as possilbe. 
<<<<<<< HEAD
 * not use in using a 128 or 256-bit cypher for 32 bits
 * __make_gatekey is plenty unique for this purpose
 * get_random_u32 is for intenal users
 */
u32 get_random_u32(void)
{
  u32 anvil __latent_entropy;
  u64 gatekey = __make_gatekey(&anvil);
  _unique_key(&anvil, gatekey, sizeof(anvil));
=======
 */
u32 get_random_u32(void)
{
  u32 anvil;
  extract_crng_user(&anvil, sizeof(anvil));
  return anvil;
}

/*
 * There are many times when we need another opinion. 
 * Ideally that would come from another source, such as arch_get_random_seed_long()
 * When we don't have a arch_get_random_seed_long, then we'll use ourselves as a source.
 * 
 * Failure is not an option.
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
         anvil ^= random_get_entropy();
      }
  }
  //anvil might still be zero - sure this could have been an unlucky roll
  // - but it also could be hardware letting us down, we can't tell the differnece.
  //The caller needs somthing
  if(anvil == 0)
  {
    u64 mop;
    u64 gatekey;
    //We know one source that won't let us down.
    __make_gatekey(&gatekey);

    //The caller is likely stacking PRNG, we can help.
    //Lets use the keypool with a jump table -
    //this jumptable pattern follows a similar pattern to the AES counterpart.
    u64 hammer_addr = (u64)gatekey;
    u64 anvil_addr = (u64)runtime_entropy[hammer_addr];
    //If we choose the same point then we xor the same values.
    //Fall to either side, don't prefer one side.
    if((hammer_addr % POOL_SIZE_BITS) == (anvil_addr % POOL_SIZE_BITS))
    {
      //flip a coin
      anvil_addr += (hammer_addr % 2) ? 8 : -8;
    }

    //Populate the anvil with PRNG
    xor_bits(&anvil, runtime_entropy, sizeof(runtime_entropy), anvil_addr, sizeof(anvil));
    //Make this key distict from a global source - not PRNG
    anvil ^= gatekey;
    //Strike the PRNG hammer
    xor_bits(&anvil, runtime_entropy, sizeof(runtime_entropy), hammer_addr, sizeof(anvil));

    //Establish an additional point of PRNG to clean our entry point.
    int mop_point = (int)runtime_entropy[key_point] % (POOL_SIZE_BITS/8);
    if(mop_point == start_point)
    {
      mop_point += (key_point % 2) ? 8 : -8;
    }
    //Get another point of PRNG to scrub the keypool.
    mop ^= (u64)*(runtime_entropy + mop_point);

    //The start_point was used as an entry point for PRNG and to generate a jump
    //Removing this value from the pool will mean that (source,key_point) won't be used again.
    xor_bits(runtime_entropy, mop, sizeof(mop), hammer_addr, sizeof(mop));
    start_point = 0;
    key_point = 0;
    mop = 0;
  }
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  return anvil;
}

/*
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
void _add_unique(uint8_t unique[], u64 gatekey, int nbytes)
{
<<<<<<< HEAD
  u64 anvil_addr = gatekey % POOL_SIZE;
  u64 next_jump = 0;
=======
  uint add_point = gatekey % POOL_SIZE;
  uint next_jump = 0;
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  //Copy bytes with a jump table - O(n)
  for(int i = 0; i < nbytes;i++)
  {
    //Pick a random point to jump to
    //Add in the gatekey so this jump path is distict
<<<<<<< HEAD
    next_jump = ((u64)runtime_entropy[anvil_addr] + gatekey) % POOL_SIZE;
    //A strike
    runtime_entropy[anvil_addr] ^= unique[i];
    anvil_addr = next_jump;
  }
  next_jump = 0;
  anvil_addr = 0;
}

/*
 * Obtain a univerasally unique value without locks
 *
 * A lock isn't needed because no two threads will be able to follow the same path.
 * 
 * The gatekey and state of the keypool is used to derive 4 jump distinct points.
 * It is like taking 4 MRI scans of a sand castle, then putting them in a XOR killidiscope.
 * That is the final key.
 * The chance of selectin 4 paths at random with a POOL_SIZE of 1024 is 2^52
 * This isn't the 2^128 or 2^256 that we want to expose as an interface.
 *
 * Each of the four layers must be unique, to prevent a^a=0
 * 
 */
void _get_unique(uint8_t unique[], u64 gatekey, int nbytes)
{
  //The caller has the option of stacking PRNG
  //Lets use the keypool with a jump table -
  //this jumptable pattern follows a similar pattern to the AES counterpart.
  u64 first_layer = gatekey;
  u64 second_layer = 0;
  u64 third_layer = 0;
  u64 fourth_layer = 0;
  int upper_bound = 0;
  //A mop for cleanup
  int mop_index = 0;
  u64 mop __latent_entropy;
  //A distinct mop is a better mop
  mop ^= gatekey;

  //We can't produce any more than POOL_SIZE bytes per position
  for(int chunk; nbytes >= 0; nbytes-=chunk)
  {
    //After POOL_SIZE bytes we need four new points
    chunk = __min(POOL_SIZE, nbytes);
    int current_pos = nbytes - chunk;

    mop_index = mop % POOL_SIZE_BITS;
    //Establish an additional point for cleaning up our tracks
    //We XOR the mop with a good source of PRNG - now the mop is "clean"
    xor_bits(&mop, runtime_entropy, sizeof(runtime_entropy), mop_index, sizeof(mop));
    //Using this mop we clean up key points immeditaly after use.

    //We need a unique value from a global buffer
    //Use the mop to clean the state ahead of ths jump
    //We modify it, read it, then modify it
    //We want to maintain global uniqueness, local uniqueness, and secrecy.
    runtime_entropy[first_layer % POOL_SIZE] ^= (u16)mop+6;
    second_layer = (u64)runtime_entropy[first_layer % POOL_SIZE];
    //Make our jump path locally unique
    second_layer ^= gatekey;
    //If we choose the same point then we XOR the same values.
    //Fall to either side, don't prefer one side.
    if((first_layer % POOL_SIZE_BITS) == (second_layer % POOL_SIZE_BITS))
    {
      //flip a coin, move a layer
      first_layer += (second_layer % 2) ? 8 : -8;
    }

    //Get our first layer in place
    xor_bits(&unique + current_pos, runtime_entropy, sizeof(runtime_entropy), first_layer, chunk);
    //Cleanup our keyspace
    xor_bits(runtime_entropy, &mop+4, 2, first_layer, 2);
    //Add the next layer
    xor_bits(&unique + current_pos, runtime_entropy, sizeof(runtime_entropy), second_layer, chunk);
    xor_bits(runtime_entropy, &mop+2, 2, second_layer,2);

    //We'll generate a new jumppoint that is unique to us
    //Move the anvil and mave sure it doesn't overlap
    //we are avoiding a^a=0 in constant time.
    if((first_layer % POOL_SIZE_BITS) < (second_layer % POOL_SIZE_BITS))
    {
      upper_bound = second_layer % POOL_SIZE_BITS;
      third_layer = (u64)unique % ((first_layer % POOL_SIZE_BITS) - 1);
    }
    else
    {
      upper_bound = first_layer % POOL_SIZE_BITS;
      third_layer = (u64)unique % ((second_layer % POOL_SIZE_BITS) - 1);
    }
    //This layer is distinct
    xor_bits(&unique + current_pos, runtime_entropy, sizeof(runtime_entropy), third_layer, chunk);
    xor_bits(runtime_entropy, &mop, 2, third_layer,2);

    //Now for the final layer
    fourth_layer = (u64)unique ^ gatekey;
    //Did we get lucky and get a unique point?
    if(fourth_layer % POOL_SIZE_BITS == first_layer % POOL_SIZE_BITS ||
       fourth_layer % POOL_SIZE_BITS == second_layer % POOL_SIZE_BITS||
       fourth_layer % POOL_SIZE_BITS == third_layer % POOL_SIZE_BITS )
    {
      //There is a 3/POOL_SIZE_BITS we'll get an a^a collision.
      //push the forth layer above our upper bound
      fourth_layer = upper_bound + 1;
      //Very unliekly, but the upper and lower bounds could be next to eachtother.
      if(fourth_layer % POOL_SIZE_BITS == third_layer % POOL_SIZE_BITS)
      {
        fourth_layer++;
      }
    }
    //Add the final layer
    xor_bits(&unique + current_pos, runtime_entropy, sizeof(runtime_entropy), fourth_layer, chunk);

    //Make sure the mop is clean
    //There is a small chance we'll reuse the same mop_index, so the value must change
    xor_bits(runtime_entropy, &unique + current_pos, sizeof(runtime_entropy), mop_index, sizeof(mop));
    
    //Change our inital layer by 1 byte
    //If we need more blocks then keep rotating our first layer.
    first_layer += 8;
  }

  first_layer = 0;
  second_layer = 0;
  third_layer = 0;
  fourth_layer = 0;
  mop = 0;
  nbytes = 0;
  gatekey = 0;
}

/*
 * There are many times when we need another opinion. 
 * Ideally that would come from another source, such as arch_get_random_seed_long()
 * When we don't have a arch_get_random_seed_long, then we'll use ourselves as a source.
 * 
 * Failure is not an option.
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
  //The caller needs somthing
  if(anvil == 0)
  {
    u64 gatekey;
    //We know one source that won't let us down.
    gatekey = __make_gatekey(&gatekey);
    _get_unique(&anvil, gatekey, sizeof(anvil));
  }
  return anvil;
=======
    next_jump = ((uint)runtime_entropy[add_point] + gatekey) % POOL_SIZE;
    //An attacker should not be able to determine how add_point changes
    runtime_entropy[add_point] ^= unique[i];
    add_point = next_jump;
  }
  next_jump = 0;
  add_point = 0;
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
}

/*
 * The goal of _unique_key is to return universally-unique key material
 * that an attacker cannot guess.
 *
 * The race condition at entry_byte_boundry helps us obtain a value that is difficult to guess.
 * We XOR some new uncertity into a global buffer that is being acted upon by other threads. 
 * If the new uncertity is applied, then the resulting value is more unique than previous invokation.
 * If the new uncertity isn't applied, then this was due to new uncertity being introdued to the global buffer.
 * Either outcome - the device driver wins because the key is unique.
 *
 * We make sure our local copy is augmented from the global state to insure a univerally-unique state.
 * It is possilbe for two or more threads to have the same jump offsets, however -
 * Every (offset % POOL_SIZE) produes a 1/POOL_SIZE chase where two get_universally_unique_key() would return the same state. 
 * no two threads can ever have the same gatekey - so the result is unique.
*/
<<<<<<< HEAD
void _unique_key(u64 uu_key[], u64 gatekey, int nbytes)
{
  u64 anvil;
  anvil ^= _alternate_rand();
  //Make sure our local state is distinct from any global state
  //We don't have a word for the number 2^52
  //We can make it an even less likely collision 
  // - by adding an additonal 128 bits of variablity.
  xor_bits(uu_key, &gatekey, sizeof(gatekey), 0, nbytes);
  xor_bits(uu_key, &anvil, sizeof(anvil), sizeof(gatekey), nbytes);

  //Pull in layers of PRNG
  _get_unique(uu_key, gatekey, nbytes);

  gatekey = 0;
  anvil = 0;
=======
void _unique_key(uint8_t uu_key[], u64 gatekey, int nbytes)
{
  u64 anvil;
  u64 mop;
  //Jump table, use the last point as the next point.
  //Add in the gatekey so that this jump path is distinct.
  //int entry_point = gatekey % POOL_SIZE_BITS;
  u64 jump_point;
  u64 look_point;
  u64 entry_point;

  //This jump point is distinct based on the state of (gatekey, keypool)
  //If a race condition changd the value, then it will still be distinct
  xor_bits(&entry_point, runtime_entropy, POOL_SIZE, gatekey, sizeof(look_point));
  anvil = _alternate_rand() ^ gatekey;

  uint16_t * anvil_ptr = &anvil;
  uint16_t hammer_idx = anvil_ptr[1] ^ anvil_ptr[3];
  uint16_t anvil_idx = anvil_ptr[2] ^ anvil_ptr[4];

  hammer_idx = hammer_idx % POOL_SIZE;
  anvil_idx = anvil_idx % POOL_SIZE;

  hammer_idx = (uint16_t)entry_point[hammer_idx] % POOL_SIZE_BITS;
  anvil_idx = (uint16_t)entry_point[anvil_idx] % POOL_SIZE_BITS;

  //What is the current jump point for our gatekey?
  //xor_bits(&look_point, runtime_entropy, POOL_SIZE, anvil, sizeof(look_point));

  //Strike the anvil for a nonce
  //_alternate_rand() is external and could be faulty
  //Even if _alternate_rand() returns 0 every time
  //look_point alone will change enough for this jump
  //mop = _alternate_rand();// ^ (u64)look_point;
  //xor_bits(&entry_point, runtime_entropy, look_point, gatekey, sizeof(anvil));
  //uint16_t * anvil_ptr = &anvil;
  //uint16_t mop = anvil_ptr[1] ^ anvil_ptr[2];

  //We want to choose a key at random.
  //Introduce uncertity by modifying a global buffer
  //xor_bits(runtime_entropy, mop, POOL_SIZE, gatekey, sizeof(mop));
  //xor_bits(&jump_point, runtime_entropy, POOL_SIZE, entry_point, sizeof(look_point));

  //clean the complament because; a^b == b^a
  //mop = anvil_ptr[3] ^ anvil_ptr[4];
  //xor_bits(runtime_entropy, mop, POOL_SIZE, entry_point, sizeof(mop));
 
  //There is a 1/POOL_SIZE_BITS chance well jump to the same spot
  //xor'ing two identical values produces zeros - we will avoid this with a shift
  if((hammer_idx % POOL_SIZE_BITS) == (anvil_idx % POOL_SIZE_BITS))
  {
     //Flip a coin and go someplace new and interesting: 
    //Move the hammer so the hammer and anvil are in differnt spots.
     if(runtime_entropy[hammer_idx] % 2)
     {
        hammer_idx += nbytes;
     }
     else
     {
        hammer_idx -= nbytes; 
     }
  }

  //If uu_key is populated, it will become a seed
  //If not, copy over bits from our first point:
  xor_bits(uu_key, runtime_entropy, POOL_SIZE, anvil_idx, nbytes);

  //Make sure our local state is distinct from any global state.
  xor_bits(uu_key, anvil, sizeof(anvil), 8, nbytes);

  //XOR another distinct reigon of PRNG
  //This will make our output to be closer to Gaussian noise, where anvil is not
  xor_bits(uu_key, runtime_entropy, POOL_SIZE, hammer_idx, nbytes);
  
  anvil = 0;
  look_point = 0;
  jump_point = 0;
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
}

/*
 * This function extracts randomness from the Keypool, and
 * returns it in a userspace buffer.
 *
 * This is where users get their entropy from the random.c 
 * device driver (i.e. reading /dev/random)
 */
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes){
    //Ok, we need somthing bigger, time for OFB.
    uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
    uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
    AesOfbContext   aesOfb; 
    size_t amountLeft = nbytes;
    int chunk;

    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this gatekey.
    uint64_t gatekey = __make_gatekey(__user_buf);
    
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array. 
    _unique_key(local_iv, gatekey, BLOCK_SIZE);

    //Select the key:
    _unique_key(local_key, gatekey, BLOCK_SIZE);

    //Generate one block of PRNG
<<<<<<< HEAD
    AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
    
    //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
    AesOfbOutput(&aesOfb, __user_buf, nbytes);
=======
    AesOfbInitialiseWithKey( &aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
    
    //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
    AesOfbOutput( &aesOfb, __user_buf, nbytes);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

    //Zero out memeory to prevent backtracking
    memzero_explicit(local_iv, sizeof(local_iv));
    memzero_explicit(local_key, sizeof(local_iv));
    gatekey = 0;
    //Cleanup complete 
    //at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
}

// This is the /dev/urandom variant.
// it is simlar to the algorithm above, but more time is spent procuring stronger key mateiral.
// the user is willing to wait, so we'll do our very best.
// when this method completes, the keypool as a whole is better off, as it will be re-scheduled.
<<<<<<< HEAD
 /*
 *
 * Rolling accumulator keys
 * Key, IV, and Image accumulate entropy with each operation
 * They are never overwritten, only XOR'ed with the previous value
 */
static ssize_t extract_crng_user_unlimited(uint8_t *__user_buf, size_t nbytes)
{
    //Three "pools" that will be filled
    uint8_t   key_accumulator[BLOCK_SIZE] __latent_entropy;
    uint8_t   iv_accumulator[BLOCK_SIZE] __latent_entropy;
    uint8_t   image_accumulator[BLOCK_SIZE] __latent_entropy;
    AesOfbContext   aesOfb;
    size_t amountLeft = nbytes;
    int chunk;
=======
static ssize_t extract_crng_user_unlimited(uint8_t *__user_buf, size_t nbytes)
{
    uint8_t   key_accumulator[BLOCK_SIZE] __latent_entropy;
    uint8_t   iv_accumulator[BLOCK_SIZE] __latent_entropy;
    uint8_t   image_accumulator[BLOCK_SIZE] __latent_entropy;
    u64 alt_accumulator __latent_entropy;
    AesOfbContext   aesOfb;
    size_t amountLeft = nbytes;
    int chunk;
    //The user is expecting to get the best restuls.
    //Watch out, unlimited is coming through - lets tidy the place up. 
    //crng_reseed(runtime_entropy, runtime_entropy);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

    //User input is combined with the entropy pool state to derive what key material is used for this gatekey.
    uint64_t gatekey = __make_gatekey(__user_buf);
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array.

    //The key, IV and Image will tumble for as long as they need, and copy out PRNG to the user. 
    while( amountLeft > 0 )
    {
<<<<<<< HEAD
        chunk = __min(amountLeft, BLOCK_SIZE );
        //rescheudle the key each round - it will be more difficult to guess
        _unique_key(key_accumulator, gatekey, BLOCK_SIZE);
        _unique_key(iv_accumulator, gatekey, BLOCK_SIZE);
        _unique_key(image_accumulator, gatekey, BLOCK_SIZE);

        //Generate one block of PRNG
        AesOfbInitialiseWithKey(&aesOfb, key_accumulator, (BLOCK_SIZE/8), iv_accumulator );
        //Image encrypted in place.
        AesOfbOutput(&aesOfb, image_accumulator, chunk);
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        memcpy(__user_buf + (nbytes - amountLeft), image_accumulator, chunk);
=======
        chunk = __min( amountLeft, BLOCK_SIZE );

        //rescheudle they key each round - it will be more difficult to guess
        //Follow the twist, the iv we chose tells us which key to use
        //This routine needs the hardest to guess key in constant time.
        _unique_key(iv_accumulator, gatekey, BLOCK_SIZE);
        _unique_key(image_accumulator, gatekey, BLOCK_SIZE);
        _unique_key(key_accumulator, gatekey, BLOCK_SIZE);

        //Use an outside source to make sure this key is unique.
        //This is one way we can show that this PRNG stream doesn't have a period
        //By including an outside source every block, we ensure an unlimited supply of PRNG.
        //Even if a hardware rand isn't available, we'll generate a random value without AES.
        //This step raises the bar, and some PRNGs will use zeros here:
        alt_accumulator ^= _alternate_rand();
        //Drop an anvil on it - make our key material more unique
        xor_bits(key_accumulator, alt_accumulator, sizeof(key_accumulator), 0, sizeof(alt_accumulator));
        //xor_bits(local_image, anvil, sizeof(local_image), 0, sizeof(anvil));

        //Generate one block of PRNG
        AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
        //Image encrypted in place.
        AesOfbOutput(&aesOfb, local_image, chunk);
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        memcpy(__user_buf + (nbytes - amountLeft), local_image, chunk);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
        amountLeft -= chunk;
        //More work?
        if(amountLeft > 0)
        {
          //At the end of the loop we get:
          //The cipher text from this round is in local_image, which in the input for the next round
          //The IV is a PRNG feedback as per the OFB spec - this is consistant
          //A new secret key is re-chosen each round, the new IV is used to choose the new key.
          //Using an IV as an index insures this instance has a key that is unkown to others - at no extra cost O(1).
<<<<<<< HEAD

          //This is the resulting IV unused from AES-OFB, intened to be used in the next round:
          xor_bits(iv_accumulator, aesOfb.CurrentCipherBlock, BLOCK_SIZE, 0, BLOCK_SIZE);
        }
     }
    //Cover our tracks.
    memzero_explicit(image_accumulator, sizeof(image_accumulator));
    memzero_explicit(iv_accumulator, sizeof(iv_accumulator));
    memzero_explicit(key_accumulator, sizeof(key_accumulator));
=======
          
          //This is the resulting IV unused from AES-OFB, intened to be used in the next round:
          xor_bits(local_iv, aesOfb.CurrentCipherBlock, BLOCK_SIZE, 0, BLOCK_SIZE);
        }
     }
    //Cover our tracks.
    memzero_explicit(local_image, sizeof(local_image));
    memzero_explicit(local_iv, sizeof(local_iv));
    memzero_explicit(local_key, sizeof(local_key));
    anvil = 0;
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
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
  seed ^= _alternate_rand();
  
  //Seed is 64 bits, so lets squeeze ever bit out of that.
  fast_pool[0] ^= seed;
  fast_pool[1] ^= seed >> 32;
  fast_pool[2] ^= gatekey;
  fast_pool[3] ^= gatekey >> 32;

  //_mix_pool_bytes() is great and all, but this is called a lot, we want somthing faster. 
  //A single O(1) XOR operation is the best we can get to drip the entropy back into the pool
<<<<<<< HEAD
  _add_unique(fast_pool, gatekey, 32);
}

=======
  _add_unique(fast_pool, gatekey, 0, 32);
}



>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
static void crng_reseed(struct crng_state *crng, struct entropy_store *r)
{
  AesOfbContext   aesOfb; 
  unsigned long flags;
  int crng_init;
  int   i, num;
  u64 gatekey; 
<<<<<<< HEAD
  u8         fresh_prng[POOL_SIZE];
=======
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  uint8_t    local_iv[BLOCK_SIZE] __latent_entropy;
  uint8_t    local_key[BLOCK_SIZE] __latent_entropy;
  union {
    __u8  block[BLOCK_SIZE];
    __u32 key[8];
  } buf;

  //Get entry to the key pool
  gatekey = __make_gatekey(crng);
  // fetch an IV in the current state.
  _unique_key(&local_iv, gatekey, BLOCK_SIZE);
  _unique_key(&local_key, gatekey, BLOCK_SIZE);

  //Output of extract_crng_user() will XOR with the current crng->state
  extract_crng_user(crng->state, sizeof(crng->state));
  //encrypt the entire entropy pool with the new key:
  AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv);
  //Hardware accelerated AES-OFB will fill this request quickly and cannot fail.
  AesOfbOutput(&aesOfb, crng->state, POOL_SIZE); 

<<<<<<< HEAD
  //We bathe in the purest PRNG
  extract_crng_user_unlimited(fresh_prng, POOL_SIZE);
  _add_unique(fresh_prng, gatekey, POOL_SIZE);

  memzero_explicit(&buf, sizeof(buf));
  memzero_explicit(&local_iv, sizeof(local_iv));
  memzero_explicit(&local_key, sizeof(local_key));
  memzero_explicit(fresh_prng, POOL_SIZE);
  crng->init_time = jiffies;
=======
  memzero_explicit(&buf, sizeof(buf));
  memzero_explicit(&local_iv, sizeof(local_iv));
  memzero_explicit(&local_key, sizeof(local_key));
  crng->init_time = jiffies;
  jump_point = 0;
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
  gatekey = 0;

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
<<<<<<< HEAD
  uint8_t    *anvil;
  u64        gatekey;
  gatekey  = __make_gatekey(&anvil);
=======
  int        jump_point = 0;
  uint8_t    *anvil;
  u64        gatekey;
  __make_gatekey(&anvil);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
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
      &anvil,
      gatekey,
      &gatekey
  };

  //Start with noise in the pool for the jump table.
  //This will ensure that _unique_key() doesn't depend on __latent_entropy
  crng_reseed(runtime_entropy, runtime_entropy);

  //Gather Compile time entropy
  //  - GCC's latent_entropy on anvil, local_key and local_iv
  //  - machine code of this method (EIP), and anything near by.
  //  - machine code of whoever called us, and anything near by.
  //Copy recentally used instructions from the caller
<<<<<<< HEAD
  _add_unique(_RET_IP_ - nbytes_needed, gatekey, nbytes_needed);
  _add_unique(_RET_IP_, gatekey, nbytes_needed);
  //Copy from the instructions around us:
  _add_unique(_THIS_IP_ - nbytes_needed, gatekey, nbytes_needed);
  _add_unique(_THIS_IP_, gatekey, nbytes_needed);
=======
  jump_point = _add_unique(_RET_IP_ - nbytes_needed, gatekey, jump_point, nbytes_needed);
  jump_point = _add_unique(_RET_IP_, gatekey, jump_point, nbytes_needed);
  //Copy from the instructions around us:
  jump_point = _add_unique(_THIS_IP_ - nbytes_needed, gatekey, jump_point, nbytes_needed);
  jump_point = _add_unique(_THIS_IP_, gatekey, jump_point, nbytes_needed);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

  //Gather Runtime Entropy
  //  - Data from the zero page
  //  - Memory addresses from the stack and heap
  //  - Unset memory on the heap that may contain noise
  //  - Unallocated memory that maybe have used or in use
  //Copy from the zero page, contains HW IDs from the bios
<<<<<<< HEAD
  _add_unique(ZERO_PAGE, gatekey, nbytes_needed);
  //XOR untouched memory from the heap - any noise here is golden.
  _add_unique(local_iv, gatekey, nbytes_needed);
  //XOR memory from the heap that we haven't allocated
  //is there a part of the bss that would be good to copy from?
  _add_unique(local_iv + nbytes_needed, gatekey,  nbytes_needed);
  _add_unique(local_iv - nbytes_needed, gatekey, nbytes_needed);
=======
  jump_point = _add_unique(ZERO_PAGE, gatekey, jump_point, nbytes_needed);
  //XOR untouched memory from the heap - any noise here is golden.
  jump_point = _add_unique(local_iv, gatekey, jump_point, nbytes_needed);
  //XOR memory from the heap that we haven't allocated
  //is there a part of the bss that would be good to copy from?
  jump_point = _add_unique(local_iv + nbytes_needed, gatekey, jump_point,  nbytes_needed);
  jump_point = _add_unique(local_iv - nbytes_needed, gatekey, jump_point, nbytes_needed);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

  //twigs when wrapped together can become loadbearing
  //_unique_key() might not be not safe at this point  
  // - but it is unique enough as a seed.
  //We will use it as a jump table, to get chunks.
  //Lets allocate a chunk of memory from the heap
  //we are not setting the memory any noise here is gold
  for(int block_index=0; block_index < nbytes_needed; block_index+=BLOCK_SIZE){
    //Chunk it in one at a time - which will cause writes to the table.
    _unique_key(anvil + block_index, gatekey, BLOCK_SIZE);
  }

  int number_of_points = sizeof(points_of_interest)/sizeof(points_of_interest[0]);
  for(int i = 0;i < number_of_points; i++){
    u64 * work_ptr;
    u32 work_idx;
    //Make anvil circular
    work_idx = (i * 8) % sizeof(anvil);
    work_ptr = &anvil[work_idx];
    *work_ptr ^= (u64)points_of_interest[i];
  }

  //Copy memory from the stack that was used before our execution
<<<<<<< HEAD
  _add_unique(anvil + nbytes_needed, gatekey,  nbytes_needed);
  //xor_bits(anvil, anvil + nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Copy memory from the stack that hasn't been used
  _add_unique(anvil - nbytes_needed, gatekey, nbytes_needed);
  //xor_bits(anvil, anvil - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Lets what we have now to build stronger keys
  _add_unique(anvil, gatekey, nbytes_needed);
=======
  jump_point = _add_unique(anvil + nbytes_needed, gatekey, jump_point,  nbytes_needed);
  //xor_bits(anvil, anvil + nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Copy memory from the stack that hasn't been used
  jump_point = _add_unique(anvil - nbytes_needed, gatekey, jump_point, nbytes_needed);
  //xor_bits(anvil, anvil - nbytes_needed, nbytes_needed, nbytes_needed, nbytes_needed);
  //Lets what we have now to build stronger keys
  jump_point = _add_unique(anvil, gatekey, jump_point, nbytes_needed);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

  //We have added a lot to the pool at this point.
  //_unique_key will do its job - the IV and Key will be _globally_ unique
  _unique_key(local_iv, gatekey, BLOCK_SIZE);
  _unique_key(local_key, gatekey, BLOCK_SIZE);
  //Reschedule the key so that it is more trustworthy cipher text:
  AesOfbInitialiseWithKey(&aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
  //Make the plaintext input used in key derivation distinct:
  _unique_key(local_iv, gatekey, BLOCK_SIZE);
  _unique_key(local_key, gatekey, BLOCK_SIZE);  
  AesOfbOutput(&aesOfb, local_iv, sizeof(local_iv));
  AesOfbOutput(&aesOfb, local_key, sizeof(local_key));
  //A block cipher is used as a KDF when we have low-entropy
  //The keys will be pure PRNG from a trusted block cipher like AES:
  AesOfbInitialiseWithKey( &aesOfb, local_key, (BLOCK_SIZE/8), local_iv );
  //Use this new block-cipher PRNG as the hammer for the anvil
  AesOfbOutput(&aesOfb, anvil, nbytes_needed);
  //We don't need fast_mix to shuffle our bits, the block cipher has done enough of this.
<<<<<<< HEAD
  _add_unique(anvil, gatekey, nbytes_needed);
=======
  jump_point = _add_unique(anvil, gatekey, jump_point, nbytes_needed);
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d

  //Things are better, the driver is warm
  //It is reasonable to assume _unique_key() is globally unique
  //Lets take /dev/urandom for a spin:
  extract_crng_user_unlimited(anvil, nbytes_needed);

  //Add our best feedback-PRNG as a source
<<<<<<< HEAD
  _add_unique(anvil, gatekey, nbytes_needed);
  0;

  //Up and running.
=======
  jump_point = _add_unique(anvil, gatekey, jump_point, nbytes_needed);
  jump_point = 0;

  //Flying now.
>>>>>>> 50c0f04b00e137e0fd1bff8d030e10b21637c76d
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
    //Assume this is the normal startup procedure from the kernel.
    //load_file(runtime_entropy, POOL_SIZE);
    //find_more_entropy_in_memory(POOL_SIZE);

    //let's assume the entrpy pool is the same state as a running linux kernel
    //start empty
    memset(local_block, 0, sizeof local_block); 
 
    u32 small = get_random_u32();
    u64 mid = get_random_u64();
    printf("%lu", small);
    printf("\n\n");
    printf("%lu", mid);
    printf("%llu", mid);
    printf("\n\n");
    u64 gatekey;
    gatekey = __make_gatekey(&gatekey);
    printf("gatekey:%llu",gatekey);
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
