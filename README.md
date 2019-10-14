# Keypool Random

## Motivation:

Any improvement in the linux kernel's performance has a dramatic effect on power usage worldwide.  If we can improve the efficiency of Linux’s random number generator by removing bottlenecks then our cell-phone battery will last longer, our data centers will draw less electricity, and the technology we love will produce less CO2.   None of this should be done at sacrificing basic security needs or violating any NIST requirement.  We might be able to get more out of the existing entropy pool in the Linux Kernel using AES-OFB, this project is exploring what that looks like.

## Goals:
 - Follow NIST security requirements.
 - Provide a high bar of security while being a very efficient source of random values 
 - Function-level security where all Inputs are untrusted
 - All outputs are AES cipher-text 
 - Don’t trust input from userspace or from hardware
 - No worse than the platform's hardware rand, and better than any backdoored hardware rand. 
 - Race conditions seem to help with the generation of random values and maintaining function-level security.

## Foreword:

When I first read random.c in the linux kernel it was magic - making a stream of security random PRNG out of thin air.  I initially fell in love with it because it was well written, had great documentation and provided easily understandable magic.  At first it was my favorite kernel driver, but as I learned more about Linux I started to see it more of an encumbrance.  A few things started to bother me about random.c - the first one being one of it’s means of entropy collection is a burden on heavily trafficked syscalls, like the ones used in file-io and memory allocation.  Let me ask you this, name one other kernel driver that makes unrelated syscalls slower in order for it to function? There are very few - and most of them are security features. There is a reason why it is hard to name another and that is because we have been good about avoiding this pattern in other parts of the Linux kernel - so can we avoid this pattern in random.c?

## Addressing “Entropy Depletion” in the current random.c device driver. 

We can assume AES preserves confidentiality, and it would be really big news if it stopped doing this.  If we assume the confidentiality of the pool is never undermined by its operation, then  we can also assume that the pool never drains.  Infact, a key pool has the oppocite effect, with additonal use it's state becomes less and less predictable to attackers. THe issue of running out of entropy is coming from AES Output Feedback (OFB) mode using key material that is univerally unique, and very difficult for anyone to guess.  To avoid re-using keys, and to avoid related-key attacks we overwrite the entry point into a twist table with the resulting ciphertext of an invocation.

## Locked or Lockless?

There is nothing stopping this key pool from using the existing locks, but I don’t see it as being any benefit in having them.  The session generated is a 64bit value, this isn't going to collide and I don't think it possible for two consumers of the same device to generate an identical Session ID.  This holds true due to the pidgen-hole principle, no two consumers can be in the same place at the same time - no two consumers can attempt to fill the same buffer at the same time - so this derived value can never collide. When you have a hammer, everything looks like a nail.  If you are used to writing device drivers, then you are used to writing tons of locks.  What if I were to tell you that an entropy pool is the one place where adding locks makes it less random?  Is this the one place where we can remove locks to improve efficiency and security? 

There is one part of the generation process that goes out of it's way to introduce the possibility of collision, and that is the key scheduling process.  With each round of AES, a new key is chosen from the key pool, which is a global buffer. This global buffer can have any number of threads acting upon it so the key that was copied by a given session is inherently ephemerial, and difficult for any outside observer to determine.  Again, nothing is stopping us from grabbing a key from another buffer - it is just a buffer that may or may not be undergoing a race condition is a benefit because it introduces an independent variable that an attacker is forced to account for and the defender gets absolutely free - O(1).

This project is generating data that is less reliant on time stamps, and more reliant on noise created by AES paired uncertainty derived from race conditions. The defender is stacking as many uncertainties as possible. This is an additive effect, an attacker attempting to guess the current state of the pool will become less and less confident over time..  Because only ciphertext is returned, it is impossible for an outsider to determine what order of operations where taken upon the entropy pool leading up to any given invocation. 

If we assume the entropy pool is always full enough, then we no longer need to keep locks around the entry pool counter, and urandom no longer needs to block until the entropy pool is "full enough."  However, in respect of the user’s intentions,  urandom should be a more random variant of the device driver, and a key pool could work harder to insure that the pool's state is fresh before a run, and key material used is properly disposed of.

## The period

Lets assume a pool size of 1k, or 1024 bytes, and AES-256-OFB is chosen as the means of generation.  Each bit within the entropy pool represents one pathway down a twist-table that will yield different key material.  1024 bytes, is 8192 bits, which represents 8192 unique entry points that can generate a total of 2,097,152 unique AES-256 without needing to reschedule the state of the entropy pool. A key pool is a type of entropy pool that is a dense block multi-dimensional block of keys, 

For the period of the random number generator to ever repeat; the key, iv and image need to repeat.  Even if AES-128 is chosen, these values will never repeat in the time frames that we are concerned with.

## Keypool creation

A keypool must be an entropy pool that is a multiple of the keysize of the block-cipher used, the smallest size would be just three times the block size.  So for AES-256 we would need a key pool of 768bits.  All outputs produced by the random number generator, as well as all entropy put into the pool are outputs of AES-OFB’s PRNG stream.

Three chunks will be taken from the pool and used as the Key, IV and Plaintext which will be used as input to AES-OFB.  When generating an OFB stream for a user,  we need to make sure that no two invocations could ever return the same PNRG stream. This is done with a session id that is globally unique to that invocation of device driver.  The session is comprised of the "when", and the "where" the invocation took place. The session id the accurate timestamp xor'ed with the memory address of where the random bytes need to be copied to resulting in a 64bit identifier.   Although the Session ID maybe guessable by some attackers, it is just the entropy point into the keypool twist-table, which is opaque.

By generating the IV in this way it avoids the problem of a race condition leading to an identical PRNG stream.  Even if another thread where to grab use the entropy pool at the same state, the initialization vector for that session will be universally unique, meaning that PRNG stream will be unique.  Two users cannot occupy the same session id, no matter what.

The encryption key used is always one block of the global entropy pool - and this is always the global state.  Although a given invocation could take out locks to ensure predictability - it would be better to use the entropy pool that is undergoing change because its state is difficult to guess and becomes less deterministic over time.  A race condition in how the encryption key is generated produces the intended effect - a more difficult to predict source of random values.  To finnish, the very last IV will be the most difficult to predict value a session has because it has the most unknowns contributing to its final state. This culmination of unknowns is used to overwrite the entry point to the session - making sure that the entry point to the twist table is entirely overwritten.

![AES-OFB encrypt](https://upload.wikimedia.org/wikipedia/commons/thumb/b/b0/OFB_encryption.svg/1202px-OFB_encryption.svg.png)

In the diagram above, you can see that the the PRNG output becomes the IV input to the next round. After a user's request for PRNG has been filled, the pool needs to be modified to ensure that the same path will never be taken again.   The key and image inputs for OFB are taken by an offset of the IV, so if we destory the IV then it is very unlikely that the same image and key will ever be used in conjuction again. The final IV of a given invocation is unique in a number of ways,  its seed comes from this invocation's session ID which is globally uniqe.   Additionally a single IV may or may not have been generated using multiple encryption keys, and knowing which keys is an unknown that would need to be determined.  After a given invocation the final IV is the greatest culmination of unknowns, and is the best value to add to the keypool. 

This use of the final IV is taken the same design where a stream cipher's terminating PRNG becomes the next IV.  This IV is universally unique in that no IV like this has probably ever been generated.  When using OFB mode it is vital that the IV is never re-used, this problem is solved by replaing the old IV with a newly generated PRNG.  This step ensures that the state of the driver is fresh for the next user.
