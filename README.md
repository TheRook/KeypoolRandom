# Keypool Random

## Motivation

The goal is to improve interrupt handling performance while providing a high-quality NIST compliant /dev/random device driver. We can accomplish this by removing the need to hook the interrupt handler, which is used for all kinds of features - including reschedule the pool which will randomly penalize syscalls and really ought to be removed. In order to remove the /dev/random locks, we have to fix a broader pattern in how entropy is added and removed from the pool. 	

I don’t think the existing credit_entropy_bits does it's job very well - however it is a heavy function and we would benefit from having it moved outside of handle_irq_event_percpu() (handle.c).  This change will make every interrupt slightly faster, and avoids the possibility of one interrupt getting screwed over by being forced to reschedule the entire entropy pool.


## Theory

Sand has a number of great properties. Imagine sitting on the beach and taking a picture of sand close up, and turning it into a binary stream - that would be a difficult number to guess even if the attacker knows it is a picture of sand.  This picture of sand is so pretty good, you wouldn't need a very high resolution image - in fact maybe just 1024 bytes would be too large for anyone to guess.

When you are pouring sand into a pile, there really isn't a bottle neck.  You can just dump more and the pile grows with the addition of new material. The pile of sand isn't uniform, there are irregularities and sometimes the sand can avalanche off one side - and this is a useful property.  Our lockless keypool is a bit like a mound of sand.  It is circular, and entropy is added at a specific point, how it falls entropy falls into the pool is irregular and dependent on what has come before.


### Improvements 
Randomly rescheduling the entropy pool on an interrupt is unfair to the user.  You are saying that some random syscall is less important then YOUR internal driver state?  What the fuck kind of device driver gets away with this? We already accept a penalty, and then it is randomly worse?  And it's entirely avoidable!

This syscall pentitly unexceptable.  The rescheduling penalty must be paid for by the caller who is requesting PRNG!  Un-affiliated processes should not be penalized for just existing.  What if that user land task was trading stock, and you just decided to reschedule the pool randomly?  Because fuck them right?  (Ok, I'm sure no one actually said this - but the code is telling a different story.)

Fixing this one issue is worth fighting for, this is something that absolutely needed to be addressed in my PR.  The following performance measures should be improved:

 - boot time
 - number of locks taken out to boot linux
 - time taken for each interrupt
 - power usage
 - number of write operations to the pool

Any improvement in the linux kernel's performance will have a dramatic effect on power usage worldwide.  If we can improve the efficiency of Linux’s random number generator by removing bottlenecks then our cell-phone battery will last longer, our electric cars will go further, our data centers will draw less electricity, and the technology we love will produce less CO2.   None of this should be done at sacrificing basic security needs or violating any NIST requirement.  We might be able to get more out of the existing entropy pool in the Linux Kernel using AES-OFB, this project is exploring what that looks like.

### Differences between random and urandom

/dev/random needs to be fast, and in the past it relied on using a cryptographic primitive for expansion of PNRG to fill a given request.

urandom on the other hand uses a cryptographic primitive to compact rather than expand, we want to make sure that more entropy, and in turn more effort is used to generate more PNRG than what was needed and cryptographic operations compact down the desired size.  This is a good strategy for constructing an ‘unlimited rand’, and this strategy was adopted for a keypool rand where we have more plentiful sources PRNG to compact down.

### Features
 - Follow NIST security requirements.
 - Provide a high bar of security while being a sensibly-efficient source of random values 
 - Function-level security where all Inputs are untrusted
 - Use race conditions as a means to compound unknowns while maintaining function-level security.
 - All outputs are AES cipher-text 
 - Don’t trust input from userspace or from hardware
 - No worse than the available hardware rand, and unaffected by any known-backdoors for hardware rand. 
 - proactive security 


### Foreword

When I first read random.c in the linux kernel it was magic - making a stream of security random PRNG out of thin air.  I initially fell in love with it because it was well written, had great documentation and provided easily understandable magic. But as I learned more about Linux I started to see it more of an encumbrance.  A few things started to bother me about random.c - the first one being one of it’s means of entropy collection is a burden on heavily trafficked syscalls, like the ones used in file-io and memory allocation.  Let me ask you this, name one other kernel driver that makes unrelated syscalls slower in order for it to function? There are very few - and most of them are security features. There is a reason why it is hard to name another and that is because we have been good about avoiding this pattern in other parts of the Linux kernel - so can we avoid this pattern in random.c?

### Addressing “Entropy Depletion” in the current random.c device driver

We can assume AES preserves confidentiality, and it would be really big news if it stopped doing this.  If we assume the confidentiality of the pool is never undermined by its operation, then  we can also assume that the pool never drains.  Infact, a key pool has the opposite effect, with additional use it's state becomes less and less predictable. The issue of running out of entropy comes down to a design decision.  If you rely upon AES Output Feedback (OFB) mode using key material that is universally unique, and very difficult for anyone to guess.  To avoid re-using keys, and to avoid related-key attacks we overwrite the entry point into a twist table with the resulting ciphertext of an invocation.  In this new design, there is no limited resource to exhaust - so long as AES’s confidentiality properties remain intact.

## Locked or Lockless?

There is nothing stopping a keypool from using locks, but I don’t see it as providing any benefit.  The session ID generated is a 64bit value, and I don't think this can collide in any meaningful time frame.  No two consumers of a PRNG stream can occupy the same session id because of the pidgen-hole principle; no two consumers can be in the same place at the same time - no two consumers can attempt to fill the same buffer at the same time - so this derived value can never collide so no locks should be required.  If you are used to writing device drivers, then you are used to writing tons of locks, and when you have a hammer, everything looks like a nail.  What if a keypool is one place where adding locks undermines the intended effects?  Is this the one place where we can remove locks to improve both efficiency and security? 

Instead of avoiding race-conditions, a new key is selected from a global buffer with the intention of increasing the likelihood of reading a value that will be overwritten.  This global buffer can have any number of threads acting upon it so the key that was copied by a given session is inherently ephemerial, and difficult for any outside observer to determine.  Again, nothing is stopping us from adding locks or using a local buffer. Pulling an encryption key from a buffer that may or may not be undergoing a write operation is a benefit because it introduces an independent variable that an attacker is forced to account for and the defender gets absolutely free - O(1).

This project is generating data that is less reliant on time stamps, and more reliant on noise created by AES paired uncertainty derived from race conditions. In this design, the defender is stacking as many uncertainties as possible. Given this design uncertainty is an additive effect, an attacker attempting to guess the current state of the pool will become less and less confident over time.  Because only ciphertext is returned, it is impossible for an outsider to determine what order of operations were taken upon the entropy pool leading up to any given invocation. 

If we assume the entropy pool is always full enough, then we no longer need to keep locks around the entry pool counter, and urandom no longer needs to block until the entropy pool is "full enough."  However, in respect of the user’s intentions,  urandom should be a more random variant of the device driver, and a key pool could work harder to ensure that the pool's state is fresh before a run, and key material used is properly disposed of.

## The Period

The implementation of /dev/random is AES-OFB, so the period for one invocation is the block size of the underlying blockcipher, after this size is exhausted the IV+key will repeat leading to a repeat of the PRNG stream. If you need more than 2^256 blocks of entropy in a single buffer then you might not be the kind of user that this driver wants to serve.  Future invocations of /dev/random are independent of previous invocations, old key material is destroyed and there is no cycle here.

One place you can take a request for entropy larger than 2^256 is /dev/urandom - this interface spends extra effort so that a given session doesn't have a period.  The 'u' in urandom signifies ‘Random Read Unlimited’ - and this urandom implementation takes that quite literally.

Let us assume a pool size of 1k, or 1024 bytes, and AES-256-OFB is chosen as the means of generation.  Each bit within the entropy pool represents one pathway down a twist-table that will yield different key material.  1024 bytes, is 8192 bits, which represents 8192 unique entry points that can generate a total of 2,097,152 unique AES-256 without needing to reschedule the state of the entropy pool. A key pool is a type of entropy pool that is a dense block multi-dimensional block of keys, 

The keypool still needs to be rescheduled, and upon doing so - the state that produced the previous PRNG stream will have been overwritten with new entropy.  As a result, the key material in the keypool tumbles and is transformed by use, if AES-256 was used - then the PRNG would not repeat until the exact same IV, Key, and Image are reused, which are three distinct 256bit values. Reusing all three would cause a repeat of a single 256bit block within a single session of /dev/urandom - the rest of the stream will continue to be random because a new key is chosen is round - which is a new independent event and not cylicacal.  I think we can all agree that repeating even one block every 2^768 blocks is well, undesirable - we want a perfect device driver.  So fine, we will reschedule the keypool on a regular interval - adding new independent events.  As long as each augmentation of the keypool introduces new independent events, these values are additive and the key material produced will not cycle - /dev/urandom should be an infinite source of randomness that never repeats or has a Period of any kind (period).


## Keypool Creation

A keypool must be an entropy pool that is a multiple of the keysize of the block-cipher used, the smallest size would be just three times the block size.  So for AES-256 we would need a key pool of 768bits.  All outputs produced by the random number generator, as well as all entropy put into the pool are outputs of AES-OFB’s PRNG stream.

Three chunks will be taken from the pool and used as the Key, IV and Plaintext which will be used as input to AES-OFB.  When generating an OFB stream for a user,  we need to make sure that no two invocations could ever return the same PNRG stream. This is done with a session id that is globally unique to that invocation of device driver.  The session comprises the "when", and the "where" the invocation took place. The session id the accurate timestamp xor'ed with the memory address of where the random bytes need to be copied to result in a 64bit identifier.   Although the Session ID may be guessable by some attackers, it is just the entry point into the keypool twist-table, which is opaque - so this information doesn’t help determine what values were returned by /dev/random. 

By generating the IV in this way it avoids the problem of a race condition leading to an identical PRNG stream.  Even if another thread were to grab use the entropy pool at the same state, the initialization vector for that session will be universally unique, meaning that PRNG stream will be unique.  Two users cannot occupy the same session id or “gatekey”, no matter what.

The encryption key used is always one block of the global entropy pool - and this is always the global state.  Although a given invocation could take out locks to ensure predictability - it would be better to use the entropy pool that is undergoing change because its state is difficult to guess and becomes less deterministic over time.  A race condition in how the encryption key is generated produces the intended effect - a more difficult to predict source of random values.  To finnish, the very last IV will be the most difficult to predict value a session has because it has the most unknowns contributing to its final state. This culmination of unknowns is used to overwrite the entry point to the session - making sure that the entry point to the twist table is entirely overwritten.

![AES-OFB encrypt](https://upload.wikimedia.org/wikipedia/commons/thumb/b/b0/OFB_encryption.svg/1202px-OFB_encryption.svg.png)

In the diagram above, you can see that the PRNG output becomes the IV input to the next round. After a user's request for PRNG has been filled, the pool needs to be modified to ensure that the same path will never be taken again.   The key and image inputs for OFB are taken by an offset of the IV, so if we destroy the IV then it is very unlikely that the same image and key will ever be used in conjunction again. The final IV of a given invocation is unique in a number of ways,  its seed comes from this invocation's session ID which is globally unique.   Additionally a single IV may or may not have been generated using multiple encryption keys, and knowing which keys is an unknown value would need to be determined.  After a given invocation the final IV is the greatest culmination of unknowns, and is the best value to add to the keypool.

This use of the final IV is taken the same design where a stream cipher's terminating PRNG becomes the next IV.  This IV is universally unique in that no IV like this has probably ever been generated.  When using OFB mode it is vital that the IV is never re-used, this problem is solved by replacing the old IV with a newly generated PRNG.  This step ensures that the state of the driver is fresh for the next user.

Entropy estimation is essential (as per NIST).  Although it isn't perfect, any source needs to be measured to make sure it is safe. It is absolutely necessary that the driver knows roughly how difficult it is for an adversary to guess the numbers it produces.  But this value is a lot like an altimeter on a plane, if you are low to the ground - you it is a much bigger concern than if you are in the upper atmosphere. For this reason, entropy estimation is vital during the startup process. Much to the shagrin of hacker news and even Torvalds himself, the need to block until the pool is full is vital for the construction of any kind of entropy pool - even a keypool.  But a keypool doesn't become more predictable, and operations on the keypool do not produce a loss of any kind - so like a rocket ship it heads into deep space with a truly infinite source of randomness.

 Time is heavily used in the mainline linux random.c generation process - and adding more time when the pool is at its weakest doesn't put my mind at ease. I don't like the name of try_to_generate_randomness(), and I don't like we need this method to fill a real need. As an alternate to try_to_generate_randomness() I wrote find_entropy_in_memory().  Both methods generate X needed bytes of entropy on demand without blocking - one uses entirely time, the other uses entirely memory.  It uses memory address resolution as a kind of telescope into the depths of memory, looking for unallocated noise, and unique identifiers.


/dev/random - You spoiled mother fucker.  You litterally hooked the most heavily trafficed call in all of Linux and you cannot manage to keep the pool full?  You are like a rich kid that literally is given everything they could possibly need by their parents, but you can't spend your money wisely to save your life, so you keep dead locking your account while every other device driver looks on with envy. Get the fuck out of here /dev/random your drunk. You are spending Google's money, my money and wasting everyone's battery life.  Get your shit together man.

