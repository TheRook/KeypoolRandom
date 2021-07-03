
//https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L1271
//static DEFINE_PER_CPU(struct fast_pool, irq_randomness);
//static __initdata char *message;
//static __attribute_const__ char *;

#ifndef __attribute_const__
#define __attribute_const__
#endif
/*
#ifndef __initdata
#define __initdata	__section(.init.data)
#endif
*/

// Should be defined, points to the zero page populated by the bios
#define ZERO_PAGE               "0123456789"

/* These are for everybody (although not all archs will actually
   discard it in modules) */


#ifndef jiffies
#define jiffies		time(NULL)
#endif

#ifndef get_irq_regs
#define get_irq_regs		rand
#endif

#ifndef irq_randomness
#define irq_randomness void*
#endif
/*
#ifndef primary_crng
#define primary_crng void*
#endif
*/
#ifndef _THIS_IP_
#define _THIS_IP_ 123456
#endif
#ifndef __user
#define __user
#endif

#ifndef _LOFF_T_DEFINED
#define _LOFF_T_DEFINED
typedef long loff_t;
#endif

#ifndef _RET_IP_
#define _RET_IP_ 456789
#endif

#ifndef memzero_explicit
#define memzero_explicit 
#endif

#ifndef __latent_entropy
#define __latent_entropy 
#endif

#define INPUT_POOL_SHIFT	12
#define INPUT_POOL_WORDS	(1 << (INPUT_POOL_SHIFT-5))
#define OUTPUT_POOL_SHIFT	10
#define OUTPUT_POOL_WORDS	(1 << (OUTPUT_POOL_SHIFT-5))
#define SEC_XFER_SIZE		512
#define EXTRACT_SIZE		10
#define ENTROPY_SHIFT 3
#define ENTROPY_BITS(r) ((r)->entropy_count >> ENTROPY_SHIFT)


static const struct poolinfo {
	int poolbitshift, poolwords, poolbytes, poolfracbits;
#define S(x) ilog2(x)+5, (x), (x)*4, (x) << (ENTROPY_SHIFT+5)
	int tap1, tap2, tap3, tap4, tap5;
} poolinfo_table[] = {
	/* was: x^128 + x^103 + x^76 + x^51 +x^25 + x + 1 */
	/* x^128 + x^104 + x^76 + x^51 +x^25 + x + 1 */
	{ 128,	104,	76,	51,	25,	1 },
	/* was: x^32 + x^26 + x^20 + x^14 + x^7 + x + 1 */
	/* x^32 + x^26 + x^19 + x^14 + x^7 + x + 1 */
	{ 32,	26,	19,	14,	7,	1 },
#if 0
	/* x^2048 + x^1638 + x^1231 + x^819 + x^411 + x + 1  -- 115 */
	{ S(2048),	1638,	1231,	819,	411,	1 },

	/* x^1024 + x^817 + x^615 + x^412 + x^204 + x + 1 -- 290 */
	{ S(1024),	817,	615,	412,	204,	1 },

	/* x^1024 + x^819 + x^616 + x^410 + x^207 + x^2 + 1 -- 115 */
	{ S(1024),	819,	616,	410,	207,	2 },

	/* x^512 + x^411 + x^308 + x^208 + x^104 + x + 1 -- 225 */
	{ S(512),	411,	308,	208,	104,	1 },

	/* x^512 + x^409 + x^307 + x^206 + x^102 + x^2 + 1 -- 95 */
	{ S(512),	409,	307,	206,	102,	2 },
	/* x^512 + x^409 + x^309 + x^205 + x^103 + x^2 + 1 -- 95 */
	{ S(512),	409,	309,	205,	103,	2 },

	/* x^256 + x^205 + x^155 + x^101 + x^52 + x + 1 -- 125 */
	{ S(256),	205,	155,	101,	52,	1 },

	/* x^128 + x^103 + x^78 + x^51 + x^27 + x^2 + 1 -- 70 */
	{ S(128),	103,	78,	51,	27,	2 },

	/* x^64 + x^52 + x^39 + x^26 + x^14 + x + 1 -- 15 */
	{ S(64),	52,	39,	26,	14,	1 },
#endif
};

//All primes less than 1024
const int keypool_primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127};//, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021};


#ifndef __min
   #define __min( x, y )  (((x) < (y))?(x):(y))
#endif

//#define __printf void(1, 2);
//https://elixir.bootlin.com/linux/latest/source/arch/powerpc/boot/types.h#L14
typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef signed char		s8;
typedef short			s16;
typedef int			s32;
typedef long long		s64;

/* required for opal-api.h */
typedef u8  uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
//typedef u64 uint64_t;
typedef s8  int8_t;
typedef s16 int16_t;
typedef s32 int32_t;
//typedef s64 int64_t;

typedef u64 __u64;
typedef u32 __u32;
typedef u8 __u8;

typedef unsigned int cycles_t;

static int random_read_wakeup_bits = 64;

struct crng_state {
	__u32		state[16];
	unsigned long	init_time;
};

int crng_init = 2;


struct entropy_store;
struct entropy_store {
	/* read-only data: */
	const struct poolinfo *poolinfo;
	__u32 *pool;
	const char *name;
	struct entropy_store *pull;
	//struct work_struct push_work;

	/* read-write data: */
	unsigned long last_pulled;
	//spinlock_t lock;
	unsigned short add_ptr;
	unsigned short input_rotate;
	int entropy_count;
	int entropy_total;
	unsigned int initialized:1;
	unsigned int last_data_init:1;
	__u8 last_data[EXTRACT_SIZE];
};

u64 get_reg(int a, int b){
	return (u64)rand();
}



static __u32 const twist_table[8] = {
	0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
	0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278 };



int arch_get_random_seed_long(long *seed){
	seed = rand();
	return 1;
}
int arch_get_random_long(long *seed){
	seed = rand();
	return 1;
}
static long random_get_entropy(){
	return rand();
}

static struct crng_state primary_crng;