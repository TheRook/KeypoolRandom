# Keypool Random
A faster lockless /dev/random proposal for embedded, battery powered devices, and for users that need more performance out of Linux.

## Build instructions:

Builds with GCC on any platform, this is using scaffolding to build a local binary - it isn't linked with the mainline linux (yet).  It is just an experimental module that runs locally to prove the theory and to discuss this design.

On OSX in order to use gcc you need to run:
- xcode-select --install

On any system just run:
- ./build.sh
- ./keypool

## Motivation

This is a CSPRNG, a cryptographically-secure random number generator that is for all intensive purposes the de-facto source of randomness.  The goal is to improve Linux syscall performance while providing a high-quality NIST compliant /dev/random device driver. We can accomplish this by removing all locks, and only use O(1) operations for adding entropy.

Currently in Linux, as well as other operating systems - locks taken out to quantify how much entropy was collected.  In linux we have credit_entropy_bits() which takes out a global lock upon each invocation of handle_irq_event_percpu() (handle.c).  Having every syscall depend on the same lock causes problems, and this is a problem that we can avoid entirely.

## Theory

Sand has a number of great properties. Imagine sitting on the beach and taking a picture of sand close up, and turning it into a binary stream - that would be a difficult number to guess even if the attacker knows it is a picture of sand and what beach you were on.  This picture of sand is so pretty good, you wouldn't need a very high resolution image - in fact maybe just 1024 bytes would be too large for anyone to guess.

When you are pouring sand into a pile, there isn't a bottle neck.  One can pour as much sand as they would like and the pile grows with the addition of new material. The pile of sand isn't uniform, there are irregularities and sometimes the sand can avalanche off one side - and this is a useful property.  Our lockless keypool is a bit like a mound of sand.  It is circular, and entropy is added at a specific point as defined by its 'gatekey'.  The entropy falls into the pool is irregular and dependent on its value and what has come before.  The tests for randomness do need uniformity, and we rely upon a cryptographic primitive AES (but it could be SHA1) to satisfy the design constraints.


### Improvements 
Randomly rescheduling the entropy pool on an interrupt is unfair to the user.  No device driver or kernel subsystem should be allowed to tax other for its own function. 

The following performance measures should be improved:

 - syscall latency
 - boot time
 - number of locks taken out to boot linux
 - battery life / power usage / CO2 produced

Any improvement in the linux kernel's performance will have a dramatic effect on power usage worldwide.  If we can improve the efficiency of Linux’s random number generator by removing bottlenecks then our cell-phone battery will last longer, our electric cars will go further, our data centers will draw less electricity, and the technology we love will produce less CO2.   None of this should be done at sacrificing basic security needs or infringing on any NIST requirement..

### Differences between random and urandom

/dev/random needs to be fast - this is a provider of entropy to the user and to other kernel subsystems. It needs to be always available, safe and fast.

/dev/urandom on the other hand needs to respect the heightened security concerns of the user. urandom is short for 'unlimited random' - it has no period, and therefore never repeats. Our urandom creates a new entropy pool for each caller-instance that is repopulated upon every iteration, making it truly unlimited, and also entirely opaque to any attacker using row-hammer-like bugs to read a global state.

### Features
 - Follow NIST security requirements.
 - Works identically irregardless of hardware
 - Provide a high bar of security while being a sensibly-efficient source of random values 
 - Function-level security where all Inputs and hardware are untrusted
 - Use race conditions as a means to compound unknowns while maintaining function-level security.
 - All outputs are AES cipher-text 
 - Don’t trust input from userspace or from hardware
 - No worse than the available hardware rand, and unaffected by any known-backdoors for hardware rand. 
 - proactive security 

### Foreword

When I first read random.c in the linux kernel it was magic - making a stream of security random PRNG out of thin air.  I initially fell in love with it because I thought it was well written, it had great documentation and provided easily understandable magic. But as I learned more about Linux I started to see it more of an encumbrance.  A few things started to bother me about random.c - the first one being one of it’s means of entropy collection is a burden on heavily trafficked syscalls, like the ones used in file-io and memory allocation.  Let me ask you this, name one other kernel driver that makes unrelated syscalls slower in order for it to function? There are very few - and most of them are security features. There is a reason why it is hard to name another and that is because we have been good about avoiding this pattern in other parts of the Linux kernel - so can we avoid this pattern in random.c?

## Locked or Lockless?

Locks cannot make the stream more difficult to predict, therefore they are unnecessary.  The 'gatekey' generated is a 64bit value, and cannot collide in any meaningful time-frame.  No two consumers of a PRNG stream can occupy the same 'gatekey' because of the pidgen-hole principle; no two consumers can be in the same place at the same time - no two consumers can attempt to fill the same buffer at the same time - so this derived value can never collide so no locks should be required.  If you are used to writing device drivers, then you are used to writing tons of locks, and when you have a hammer, everything looks like a nail.  What if a 'keypool' is one place where adding locks undermines the intended effects?  Is this the one place where we can remove locks to improve both efficiency and security? 

Instead of avoiding race-conditions, a new key is selected from a global buffer with the intention of increasing the likelihood of reading a value that will be overwritten.  This global buffer that we call a 'keypool' can have any number of threads acting upon it so the keys produced are inherently ephemeral, and difficult for any outsider to  observe or otherwise determine.  Again, nothing is stopping us from adding locks, but why wait? Pulling a key from a buffer that may or may not be undergoing a write operation is a benefit because it introduces an independent variable that an attacker is forced to account for and the defender gets absolutely free.

This project is generating data that is less reliant on time stamps, and more reliant on noise created by cryptographic primitives and the uncertainty introduced by race conditions. In this design, the defender is stacking as many uncertainties as possible - an additive effect.  An attacker who is tasked with the misfortune of attempting to guess the current state of the pool will become less and less confident over time.  Because only ciphertext or post-image is returned, it is impossible for an outsider to determine what order of operations were taken upon the entropy pool leading up to any given invocation.

If we assume the entropy pool is always full enough, then we no longer need to keep locks around the entry pool counter, and urandom no longer needs to block until the entropy pool is "full enough."  However, in respect of the user’s intentions,  urandom should be a more random variant of the device driver, and the system can and will work harder to derive a higher degree of security.
