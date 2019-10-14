////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbOutput
//
//  Outputs bytes from an AES OFB stream. Key and IV are taken from command line. Bytes are output as hex
//
//  This is free and unencumbered software released into the public domain - January 2018 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "WjCryptLib/lib/WjCryptLib_AesOfb.h"
#include <time.h>
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
#define BLOCK_SIZE		256
#define BLOCK_SIZE_BITS         BLOCK_SIZE * 8
#define POOL_SIZE               BLOCK_SIZE * 4
#define POOL_SIZE_BITS          BLOCK_SIZE * 8
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct fast_pool {
        uint32_t        pool[POOL_SIZE];
        unsigned long   last;
        unsigned short  reg_idx;
        unsigned char   count;
};


struct key_pool;
struct key_pool
{
        uint32_t* key;
        uint32_t* iv;
        uint32_t* image;
};

uint32_t        runtime_entropy[POOL_SIZE];

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

/*
 * This is a fast mixing routine used by the interrupt randomness
 * collector.  It's hardcoded for an 128 bit pool and assumes that any
 * locks that might be needed are taken by the caller.
 */
static void fast_mix(uint32_t *pool)
{
	uint32_t a = pool[0],	b = pool[1];
	uint32_t c = pool[2],	d = pool[3];

	a += b;			c += d;
	b = rol32(b, 6);	d = rol32(d, 27);
	d ^= a;			b ^= c;

	a += b;			c += d;
	b = rol32(b, 16);	d = rol32(d, 14);
	d ^= a;			b ^= c;

	a += b;			c += d;
	b = rol32(b, 6);	d = rol32(d, 27);
	d ^= a;			b ^= c;

	a += b;			c += d;
	b = rol32(b, 16);	d = rol32(d, 14);
	d ^= a;			b ^= c;

	pool[3] = a;  pool[2] = b;
	pool[0] = c;  pool[1] = d;
}




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  ReadHexData
//
//  Reads a string as hex and places it in Data. *pDataSize on entry specifies maximum number of bytes that can be
//  read, and on return is set to how many were read. This will be zero if it failed to read any.
//  This function ignores any character that isn't a hex character.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    ReadHexData
    (
        char const*         HexString,          // [in]
        uint8_t*            Data,               // [out]
        uint32_t*           pDataSize           // [in out]
    )
{
    uint32_t        i;
    char            holdingBuffer [3] = {0};
    uint32_t        holdingBufferIndex = 0;
    unsigned        hexToNumber;
    unsigned        outputIndex = 0;

    for( i=0; i<strlen(HexString); i++ )
    {
        if(     ( HexString[i] >= '0' && HexString[i] <= '9' )
            ||  ( HexString[i] >= 'A' && HexString[i] <= 'F' )
            ||  ( HexString[i] >= 'a' && HexString[i] <= 'f' ) )
        {
            holdingBuffer[holdingBufferIndex] = HexString[i];
            holdingBufferIndex += 1;

            if( 2 == holdingBufferIndex )
            {
                // Have two digits now so read it as a byte.
                sscanf( holdingBuffer, "%x", &hexToNumber );
                Data[outputIndex] = (uint8_t) hexToNumber;
                outputIndex += 1;
                if( outputIndex == *pDataSize )
                {
                    // No more space so stop reading
                    break;
                }
                holdingBufferIndex = 0;
            }
        }
    }

    *pDataSize = outputIndex;
}
/*
uint32_t seedRand(uint32_t *state){
      //int32_t *state;
      //the address of state is an input value:
      int32_t val = (uint32_t)(((uint32_t)&state + time)) +state;
      state = val;
      return val;
}

int loadEntropy(uint32_t *destination, int max){
    uint32_t seedState;
    uint32_t        amountLeft;
    uint32_t        chunk;    
    AesOfbContext   aesOfb;
    uint32_t        initial_entropy[POOL_SIZE];
    //struct key_pool initial_pool;
    //runtime_pool.key = runtime_entropy;
    //runtime_pool.iv = runtime_entropy + BLOCK_SIZE;
    //runtime_pool.image = runtime_entropy +  BLOCK_SIZE + BLOCK_SIZE;
    //printf("init");
    AesOfbInitialiseWithKey( &aesOfb, initial_entropy, (BLOCK_SIZE/8), initial_entropy+BLOCK_SIZE );
    AesOfbOutput( &aesOfb, initial_entropy+BLOCK_SIZE+BLOCK_SIZE, BLOCK_SIZE/8 );
    //pack entrpy dest + time(NULL) 
    //srand(destination);i
    srand(time(NULL) + (uint32_t)&destination);
    char cur;
    FILE * seed_file;	
    seed_file = fopen("seed1", "r");
    if(seed_file){
        for (int i = 0; i < max && (cur = getc(seed_file)) != EOF; i++) {
	    destination[i]=cur;
        }    
    }else{
	for (int i = 0; i < max; i++){
            destination[i] = rand();
	}
    }

    AesOfbInitialiseWithKey( &aesOfb, initial_entropy, (BLOCK_SIZE/8), initial_entropy+BLOCK_SIZE );
    amountLeft = POOL_SIZE;
    while( amountLeft > 0 )
    {
        chunk = __min( amountLeft, BLOCK_SIZE );
        AesOfbOutput( &aesOfb, destination, chunk );
        amountLeft -= chunk;

    }
}
*/

int load_file(uint32_t *dest, int len){
  int ret = 0;
  FILE *seed_file;
  seed_file = fopen("seed", "r");
  if(seed_file != NULL){
     fread(dest, 1, len, seed_file);
     ret = 1;
  }
  return ret;
}
/*
void xor_bytes(uint32_t *dest, uint32_t *source, int len){
    for(int i =0; i < len; i++){
	dest[i] ^= source[i]; 
    }
}

void scheduleContext(AesOfbContext * aesOfb, uint32_t entropy_pool, uint64_t session){
    int first_key_offset = ((int)runtime_pool.iv % POOL_SIZE) - POOL_SIZE;
    uint32_t *chosen_iv = &entropy_pool + (((int)runtime_pool.iv + starting_point) % POOL_SIZE) - POOL_SIZE;
    uint32_t *chosen_key = &entropy_pool + (((int)runtime_pool.iv + starting_point) % POOL_SIZE) - POOL_SIZE; 
    AesOfbInitialiseWithKey( &aesOfb, runtime_pool.key, (BLOCK_SIZE/8), local_iv );
    xor_bytes(&local_iv, &session, 2);
    //runtime_pool.key = runtime_entropy + starting_point;
    runtime_pool.iv = local_iv;
    //Choose which key to use based off of an offset for this IV.
    int first_key_offset = ((int)runtime_pool.iv % POOL_SIZE) - POOL_SIZE;
    runtime_pool.key = &runtime_entropy + (((int)runtime_pool.iv + starting_point) % POOL_SIZE) - POOL_SIZE;
    runtime_pool.image = &runtime_entropy + (((int)runtime_pool.key + starting_point) % POOL_SIZE) - POOL_SIZE;
}
*/

//Copy by bit offset.
void  bitcpy( uint8_t dest[], uint8_t source[], int source_len, int bit_offset, int byte_length)
{
  int start_byte = bit_offset/32;        //The start byte to start the copy
  int pos = bit_offset%32;      //The start bit within the first byte
  for(int k = 0; k < byte_length; k++){
      //Treat the source as a circular buffer.	  
      if(start_byte + k > source_len){
 	start_byte = 0;
	if(k > source_len){
	    //Should not happen.
	    break;
	}
      }
      dest[k] = (0xffffffff >> (32-(pos))) << source[start_byte+k];
      if(k == byte_length-1){
	//end the array with the bit position compliment
	pos = 32 - (bit_offset%32);
      }else{
      	pos = 0;
      }
  }
}



/*
void keySchedule(AesOfbContext *aesOfb, uint32_t key_pool[], char * seed_address){
    //The seed address is unique context about the caller, including the time provides us with a unique session id for this run.
    uint64_t session = ((uint64_t)time(NULL) << 4) ^ (uint64_t) &seed_address;

    //For key scheduling purposes, the entropy pool acts as a twist table.
    //We want to produce the hardest to guess key in O(1), poiniter arithmatic will do the trick.
    //User input is combined with the entropy pool state to derive what key material is used for this session.
    int starting_point = (session % POOL_SIZE) - BLOCK_SIZE;
    strncpy(local_iv, runtime_entropy + starting_point, BLOCK_SIZE);
    //make sure this IV is universally unique, and distinct from any global state.
    xor_bytes(&local_iv, &session, 2);
    //runtime_pool.key = runtime_entropy + starting_point;
    runtime_pool.iv = local_iv;
    //Choose which key to use based off of an offset for this IV.
    int first_key_offset = ((int)runtime_pool.iv % POOL_SIZE) - POOL_SIZE;
    runtime_pool.key = &runtime_entropy + (((int)runtime_pool.iv + starting_point) % POOL_SIZE) - POOL_SIZE;
    runtime_pool.image = &runtime_entropy + (((int)runtime_pool.key + starting_point) % POOL_SIZE) - POOL_SIZE;
    //printf("init");
    AesOfbInitialiseWithKey( &aesOfb, runtime_pool.key, (BLOCK_SIZE/8), runtime_pool.iv );
}/

*/

//Thextract_crng_useris function's interface is taken from random.c
//This is where users get their entropy from the random.c device driver (i.e. reading /dev/random)
static ssize_t extract_crng_user(uint8_t *__user_buf, size_t nbytes){
    //uint32_t    local_key[BLOCK_SIZE];
    uint8_t    local_iv[BLOCK_SIZE];
    uint8_t    local_image[BLOCK_SIZE];
    AesOfbContext   aesOfb; 
    struct timespec starttime;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &starttime);
    size_t amountLeft = nbytes;
    int chunk;
    //Take everything about this specific call and merge it into one unique word (2 bytes).
    //User input is combined with the entropy pool state to derive what key material is used for this session.
    uint64_t session = starttime.tv_nsec ^ (uint64_t) &__user_buf;
    //For key scheduling purposes, the entropy pool acts as a kind of twist table.
    //The pool is circular, so our starting point can be the last element in the array. 
    int entry_point = session % POOL_SIZE_BITS;
    bitcpy( local_iv, runtime_entropy, POOL_SIZE, entry_point, BLOCK_SIZE);
    //make sure this IV is universally unique, and distinct from any global state.
    //xor_bytes( local_iv, session, 2);
    local_iv[0] ^= (uint32_t)session;
    local_iv[1] ^= (uint32_t)*(&session+4);

    //Choose which plaintext input we want to use based off of a hard to guess offset 
    //The iv tells us which input 'image' we chose to start the session:
    int image_entry_point = (((int)local_iv + entry_point) % POOL_SIZE_BITS);
    bitcpy( local_image, runtime_entropy, POOL_SIZE, image_entry_point, BLOCK_SIZE);
    //The key, IV and Image will tumble for as long as they need, and copy out PRNG to the user. 
    while( amountLeft > 0 )
    {
	printf("a:%i\n",amountLeft);
	chunk = __min( amountLeft, BLOCK_SIZE );
        //rescheudle they key each round
        //Follow the twist, the iv we chose tells us which key to use
        //This routine needs the hardest to guess key in constant time.
        //we add the image_entry_point to avoid using the same (iv, key) combination - which still shouldn't happen.
	int key_entry_point = ((int)local_iv + image_entry_point) % (POOL_SIZE - BLOCK_SIZE);
        //Generate one block of PRNG
        AesOfbInitialiseWithKey( &aesOfb, runtime_entropy + key_entry_point, (BLOCK_SIZE/8), local_iv );
        AesOfbOutput( &aesOfb, local_image, chunk);
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
    printf("%1x", local_image[i]);
     }
       printf("\n\n");
        //Copy it out to the user, local_image is the only thing we share, local_iv and the key are secrets.
        printf("to:%i\nsize:%i",(nbytes - amountLeft),chunk);
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
    //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
    //Encrypt our entropy point with the key material derivied in this local session
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), chunk);
    //Cleanup complete, at this point it should not be possilbe to re-create any part of the PRNG stream used.
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
    uint8_t        numBytes;
    uint8_t        i;
    uint8_t        local_block[BLOCK_SIZE*2];
    
    //Assume this is the normal startup procedure from the kernel.
    load_file(runtime_entropy, POOL_SIZE);
    
    //let's assume the entrpy pool is the same state as a running linux kernel

    memset(local_block, 0, sizeof local_block); 
    extract_crng_user(local_block, BLOCK_SIZE*2);
    printf( "\n" );
    /*for( i=0; i<BLOCK_SIZE; i++ ){
            printf( "%1x", local_block[i]);

    }
    */
    for (int i = 0; i < BLOCK_SIZE*2; i++)
    {
    printf("%1x", local_block[i]);
     }
    return 0;
}
