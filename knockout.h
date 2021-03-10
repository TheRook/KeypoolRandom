
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
typedef u64 uint64_t;
typedef s8  int8_t;
typedef s16 int16_t;
typedef s32 int32_t;
typedef s64 int64_t;

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


/*
 * This function adds bytes into the entropy "pool".  It does not
 * update the entropy estimate.  The caller should call
 * credit_entropy_bits if this is appropriate.
 *
 * The pool is stirred with a primitive polynomial of the appropriate
 * degree, and then twisted.  We twist by three bits at a time because
 * it's cheap to do so and helps slightly in the expected case where
 * the entropy is concentrated in the low-order bits.
 */
static void _mix_pool_bytes(struct entropy_store *r, const void *in,
			    int nbytes)
{
	unsigned long i, tap1, tap2, tap3, tap4, tap5;
	int input_rotate;
	int wordmask = r->poolinfo->poolwords - 1;
	const char *bytes = in;
	__u32 w;

	tap1 = r->poolinfo->tap1;
	tap2 = r->poolinfo->tap2;
	tap3 = r->poolinfo->tap3;
	tap4 = r->poolinfo->tap4;
	tap5 = r->poolinfo->tap5;

	input_rotate = r->input_rotate;
	i = r->add_ptr;

	/* mix one byte at a time to simplify size handling and churn faster */
	while (nbytes--) {
		w = rol32(*bytes++, input_rotate);
		i = (i - 1) & wordmask;

		/* XOR in the various taps */
		w ^= r->pool[i];
		w ^= r->pool[(i + tap1) & wordmask];
		w ^= r->pool[(i + tap2) & wordmask];
		w ^= r->pool[(i + tap3) & wordmask];
		w ^= r->pool[(i + tap4) & wordmask];
		w ^= r->pool[(i + tap5) & wordmask];

		/* Mix the result back in with a twist */
		r->pool[i] = (w >> 3) ^ twist_table[w & 7];

		/*
		 * Normally, we add 7 bits of rotation to the pool.
		 * At the beginning of the pool, add an extra 7 bits
		 * rotation, so that successive passes spread the
		 * input bits across the pool evenly.
		 */
		input_rotate = (input_rotate + (i ? 7 : 14)) & 31;
	}

	r->input_rotate = input_rotate;
	r->add_ptr = i;
}

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

