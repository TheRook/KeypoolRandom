// rando
// a lockless rand implamentation that conforms to NIST standards 

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

//Global runtime entropy
uint8_t runtime_entropy[POOL_SIZE];

int load_file(uint8_t dest[], int len){
  int ret = 0;
  FILE *seed_file;
  seed_file = fopen("seed", "r");
  if(seed_file != NULL){
     fread(dest, 1, len, seed_file);
     ret = 1;
  }
  return ret;
}

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
    //Now for the clean-up phase. At this point the key material in aesOfb is very hard to predict. 
    //Encrypt our entropy point with the key material derivied in this local session
    AesOfbOutput( &aesOfb, runtime_entropy + (entry_point / 8), chunk);
    //Cleanup complete, at this point it should not be possilbe to re-create any part of the PRNG stream used.
    return nbytes;
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
