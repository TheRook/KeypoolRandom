# Keypool Random
A faster lockless /dev/random proposal for embedded, battery powered devices, and for users that need more performance out of Linux.

### Build instructions:

Builds with GCC on any platform, this is using scaffolding to build a local binary - it isn't linked with the mainline linux (yet).  It is just an experimental module that runs locally to prove the theory and to discuss this design.

On OSX in order to use gcc you need to run:
- xcode-select --install

On any system just run:
- ./build.sh
- ./keypool

### Motivation

This is a CSPRNG, a cryptographically-secure random number generator that is for all intensive purposes the de-facto source of randomness.  The goal is to improve Linux syscall performance while providing a high-quality NIST compliant /dev/random device driver. We can accomplish this by removing all locks, and only use O(1) operations for adding entropy.

Currently in Linux, as well as other operating systems - a lock it used for a counter to quantify how much entropy was collected.  In linux we have credit_entropy_bits() which takes out a global lock upon each invocation of handle_irq_event_percpu() (handle.c).  Having every syscall depend on the same lock causes problems, and this is a problem that we can avoid entirely.

### Foreword

When I first read random.c in the linux kernel it was magic - making a stream of security random PRNG out of thin air.  I initially fell in love with it because I thought it was well written, it had great documentation and provided easily understandable magic. But as I learned more about Linux I started to see it more of an encumbrance.  A few things started to bother me about random.c - the first one being one of it’s means of entropy collection is a burden on heavily trafficked syscalls, like the ones used in file-io and memory allocation.  Let me ask you this, name one other kernel driver that makes unrelated syscalls slower in order for it to function? There are very few - and most of them are security features. There is a reason why it is hard to name another and that is because we have been good about avoiding this pattern in other parts of the Linux kernel - so can we avoid this pattern in random.c?

### Theory

Sand has a number of great properties. Imagine sitting on the beach and taking a picture of sand close up, and turning it into a binary stream - that would be a difficult number to guess even if the attacker knows it is a picture of sand and what beach you were on and where you were sitting.  This picture of sand is so random, you wouldn't need a very high resolution image - in fact maybe just 1024 bytes would be too large for anyone to guess.

When you are pouring sand into a pile, there isn't a bottle neck.  One can pour as much sand as they would like and the pile grows with the addition of new material. The pile of sand isn't uniform, there are irregularities and sometimes the sand will avalanche off one side - and this is a useful because it is less predictable.  Our lockless keypool is a bit like a mound of sand.  Its circular, and entropy is added at a specific point as defined by the hand that pours it - or more accurately its 'gatekey'.  As entropy falls into the pool, it's irregular and entirely dependent on what has come before.  The tests that we have for randomness require uniformity, and our implementation relies upon the cryptographic primitive AES to satisfy these design constraints - but it could be another preformat function like SHA1.  This algorithm can use either a block cipher or hash function, they both have the properties that we need, and one primitive may outperform another depending on the platform. Being flexible on which primitive is used is a good feature to have.


### Improvements 
Randomly rescheduling the entropy pool on an interrupt is unfair to the user.  No device driver or kernel subsystem should be allowed to tax others for its own function. 

The following performance measures should be improved:

 - syscall latency and timing consistency 
 - boot time
 - number of locks taken out to boot linux
 - battery life / power usage / CO2 produced

Any improvement in the linux kernel's performance will have a dramatic effect on power usage worldwide.  If we can improve the efficiency of Linux’s random number generator by removing bottlenecks then our cell-phone battery will last longer, our electric cars will go further, our data centers will draw less electricity, and the technology we love will produce less CO2.   None of this should be done at sacrificing basic security needs or infringing on any NIST requirement.

### Differences between random and urandom

/dev/random needs to be fast - this subsystem is a provider of entropy to the user and to other kernel subsystems. It needs to be always available, safe and preformat.

/dev/urandom on the other hand needs to respect the heightened security concerns of the user. urandom is short for 'unlimited random' - it has no period, and therefore never repeats. Our urandom creates a local entropy pool for each caller-instance that is repopulated upon every iteration, making it truly unlimited, and also entirely opaque to any attacker using row-hammer-like bugs to read a global state.

### Features
 - Meet or exceed NIST security requirements
 - Works identically irregardless of hardware
 - Functionally indistinguishable from a so call "true" RNG - we pass all the tests
 - Function-level security where all Inputs and hardware are untrusted
 - A design where race conditions are useful to the defender 
 - Unaffected by any known or unknown backdoors in hardware rand 
 - proactive security 

### Locked or Lockless?

Locks cannot make the stream more difficult to predict, therefore they are unnecessary.  The 'gatekey' generated is a 64bit value, and cannot collide in any meaningful time-frame.  No two consumers of a PRNG stream can occupy the same 'gatekey' because of the pidgen-hole principle; no two consumers can be in the same place at the same time - no two callers can attempt to fill the same buffer at the same time - so this derived value can never collide so no locks should be required.  If you have written device drivers before, then you have become accustomed to writing tons of locks, and when you have a hammer, everything looks like a nail.  What if a 'keypool' is one place where adding locks undermines the intended effect?  This is the one place where we can remove locks to improve both efficiency and also security.

Race conditions aren't a concern when generating keys because uniqueness is the only requirement. This global buffer that we call a 'keypool' can have any number of threads acting upon it so the keys produced are inherently ephemeral, and difficult for any outsider to observe or otherwise determine.  Again, nothing is stopping us from adding locks, but why wait? Pulling a key from a buffer that may or may not be undergoing a write operation is a benefit because it introduces an independent variable that an attacker is forced to account for and the defender gets absolutely free.

We are generating values that are less reliant on time stamps, and more reliant on noise created by cryptographic primitives and the uncertainty introduced by race conditions. In this design, the defender is stacking as many uncertainties as possible together.  An attacker who is tasked with the misfortune of attempting to guess the current state of the pool will become less and less confident over time.  Because only ciphertext or a hash is returned, it is impossible for an outsider to determine what order of operations were taken upon the entropy pool leading up to any given invocation.

Instead of seeing the pool as "empty" or "full" lets see it as "warmed up" or "cold."  If we know that the pool is warmed up then we don't need locks for counter consistency, and also urandom no longer needs to block until the entropy pool is "full enough."  However, in respect of the user’s intentions,  urandom should be a more random variant of the device driver, and the system can and will work harder to derive a higher degree of security.
