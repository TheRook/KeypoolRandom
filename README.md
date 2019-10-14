# Keypool Random

## Motivation:

Any improvement in the linux kernel's performance has a dramatic effect on power usage worldwide.  If we can improve the efficiency of Linux’s random number generator by removing bottlenecks then our cell-phone battery will last longer, our data centers will draw less electricity, and the technology we love will produce less CO2.   None of this should be done at sacrificing basic security needs or violating any NIST requirement.  We might be able to get more out of the existing entropy pool in the Linux Kernel using AES-OFB, this project is exploring what that looks like.

## Goals:
 - Follow NIST security requirements.
 - Provide a high bar of security while being a very efficient source of random values 
 - Function-level security where all Inputs are untrusted
 - All outputs are AES cipher-text 
 - Don’t trust input from userspace or from hardware
 - No worse than hardware rand, but better than the a backdoored hardware rand. 
 - Hardware random is used instead of initializing to 0’s as the current implementation does.
 - Race conditions help with the generation of random values and maintaining function-level security.

## Foreword:

When I first read random.c in the linux kernel it was magic - making a stream of security random PRNG out of thin air.  I initially fell in love with it because it was well written, had great documentation and provided easily understandable magic.  At first it was my favorite kernel driver, but as I learned more about Linux i started to see it more of an encumbrance.  A few things started to bother me about random.c - the first one being one of it’s means of entropy collection is a burden on all kernel operations that are hooked - which includes heavily trafficked syscodes like the ones used in file-io and memory allocation.  Let me ask you this, name one other kernel driver that makes unrelated syscalls slower in order for it to function? There are very few - and most of them are security features.  There is a reason why it is hard to name another and that is because we have been good about avoiding this pattern in other parts of the Linux kernel - so can we avoid this pattern in random.c?

## Addressing “Entropy Depletion” in the current random.c device driver. 

We can assume AES preserves confidentiality, and it would be really big news if it stopped doing this.  If we assume the confidentiality of the pool is never undermined by its operation, then  we can also assume that the pool never drains.  Infact, each time the key pool is use, it's state becomes less and less predictable to attackers. The current urandom relies upon the assumption that the entropy pool is draining with use and will block until the pool refills. This issue was fixed using AES Output Feedback - so now this means that urandom can be non-blocking.  However, in respect of the user’s intentions,  urandom should be a more random variant of the device driver, and a key pool could work harder to insure that the pool's state is fresh before a run, and key material used is properly disposed of.

## Locked or Lockless?

There is nothing stopping this key pool from using the existing locks, but I don’t see it as being any benefit.  The session generated is a 64bit int, this isn't going to collide and I don't think it possible for two consumers of the same device to generate an identical session id. When you have a hammer, everything looks like a nail.  If you are used to writing device drivers, then you are used to writing tons of locks.  What if I were to tell you that an entropy pool is the one place where adding locks makes it less random?  Is this the one place where we can remove locks to improve efficiency and security? 

This project is generating data that is less reliant on time stamps, and more reliant on noise created by AES paired uncertainty derived from race conditions. The defender is stacking as many uncertainties as possible. While an attacker’s certainty of entropy pool state decreases over time.  Because only ciphertext is returned, it is impossible for an outsider to determine what order of operations where taken upon the entropy pool leading up to any given invocation. 

## The period

Lets assume a pool size of 1k 1024 bytes, and AES-256-OFB is chosen.  Each bit within the entropy pool represents one pathway down a twist table that will yield different key material.  1024 bytes, produces 8192 unique entry points that can generate a total of 2,097,152 unique AES-256 without needing to reschedule the state of the entropy pool.   This entropy table is a dense block of keys.

For the period to ever repeat, the key, iv and image need to repeat.  The IV and Image are copied by a bit-boundary, yielding 2,097,152 possibilities for the same 1025bit key pool. For efficiency reasons, the key is selected by a byte boundary, yielding 1024 possible keys.


## Key Pool creation

A key pool must be an entropy pool that is a multiple of the keysize of the block-cipher used, the smallest size would be just three times the block size.  So for AES-256 we would need a key pool of 768bits.  All outputs produced by the random number generator, as well as all entropy put into the pool are outputs of AES-OFB’s PRNG stream.

Three chunks will be taken from the pool and used as the Key, IV and Plaintext input to AES-OFB.  When generating a stream for a user,  we need to make sure that no two invocations could ever return the same PNRG stream. This is done with a session id that is globally unique to that invocation of device driver.  The session is comprised of when, and where - it is the most accurate timestamp xor'ed with the memory address of where the random bytes need to be copied to.   Although the Session ID is guessable by an attacker, it is just the entropy point into the key pool twist table.

By generating the IV in this way it avoids the problem of a race condition leading to an identical PRNG stream.  Even if another thread where to grab use the entropy pool at the same state, the initialization vector for that session will be universally unique, meaning that PRNG stream will be unique. 

The encryption key used is always one block of the global entropy pool - and this is always the global state.  Although a local invocation could make a copy from the entropy pool - it would be better to use the entropy pool directly because its state becomes less deterministic over time.  This race condition produces the intended effect.  The very last IV will be a strange and difficult to predict value, as it has used one or more unknown keys.

![AES-OFB encrypt](https://upload.wikimedia.org/wikipedia/commons/thumb/b/b0/OFB_encryption.svg/1202px-OFB_encryption.svg.png)

In the diagram above, you can see that the the PRNG output becomes the IV input to the next round. After a user request for PRNG has been filled, the pool needs to be modified.   Specifically the key material used for this session needs to be destroyed, and we do this by mixing new entropy into the pool.  We take the additional block of IV, this would have been used to encrypt the next block of plaintext.  This IV is unique in a number of ways,  It’s seed comes from this session universally unique IV, and due to an intended race condition may or may not have been generated using multiple encryption keys.

In the same way that the output PRNG becomes the next IV - the universally unique, and unused output PRNG from this session becomes input to the entropy pool.  The input from the last step, overwrites the entry point into the twist table, making sure no other user from the device driver will be able to drive even remotely similar key material.

