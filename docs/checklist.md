# Checklist

The checklist reflecting the considerations in the classifications _functional_, _operational_ and _developmental_.

## Functionality

- General Off-the-record operation:
  - ☑ Maintain mixed OTRv2, OTRv3, OTRv4 sessions.
  - ☑ Persistent instance tags
  - ☑ 'Interactive DAKE' implemented as Message states i.s.o. AKE states.
  - ☑ OTRv4 extension to OTR error messages
  - ☑ Periodic heartbeat messages
  - [Queuing up messages](docs/message-queueing.md) while not in `ENCRYPTED_MESSAGES` state.
    - ☑ Basic message queueing implemented. (Cannot fully work until Double Ratchet algorithm is implemented.)
    - ☐ Message queueing configurable.  
        _This may be important as queue is flushed onto instance with first established private messaging. This may not always be desirable._
  - Client profiles:
    - ☑ Publishing of generated `ClientProfile` payloads through callback to `OtrEngineHost` (Affects _Deniability_-property.)
    - ☐ Timely refreshing Client Profile payload (due to expiration / updated Client Profile parameters)
  - ☐ Strictly isolate OTRv3 and OTRv4 interactions: only accept OTRv2/3 messages in `START`, but not in any OTRv4 state, and vice versa. Separate `FINISH` states for OTRv2/3 and OTRv4.
  - ☐ OTRv4 operating modes (OTRv3-compatible, OTRv4-standalone, OTRv4-interactive-only).
- Cryptographic primitives:
  - Ed448-Goldilocks elliptic curve
    - ☑ Temporary working solution
    - ⌛ Migrate to BouncyCastle 1.60.
  - 3072-bit Diffie-Hellman
    - ☑ Temporary working solution
    - ☐ Verify if current solution is acceptable, otherwise migrate to JCA/BC
  - ☑ ChaCha20 symmetric cipher
  - ☑ SHAKE-256
  - ☑ Ring signatures
- Key Exchange:
  - ☑ Interactive DAKE
  - ☐ Non-interactive DAKE
- Key Management:
  - Double Ratchet:
    - ☑ Generate next message keys (in-order messages)
    - ☑ Generate future message keys (skip over missing messages)
    - ☐ Implementation of Double Ratchet algorithm redesign.
  - Shared secrets management:
    - ☑ Ephemeral DH with 3072-bit parameters
    - ☑ Ephemeral ECDH based on Ed448-Goldilocks
    - ☑ Key rotation
  - ☑ Calculate _Encryption_, _MAC_ and _Extra Symmetric Key_ keys
  - ☑ Revealing used MAC keys
  - ☑ Revealing queued up MAC keys upon session expiration.
  - ☐ Revealing MAC keys generated from memorized message keys upon session expiration.
  - ☐ Periodic clean-up of "old" skipped message keys
- Message encryption/decryption:
  - ☑ In-order messages
  - ☑ In-order messages with some messages missing
  - ☐ Out-of-order messages
- Fragmentation and re-assembly:
  - ☑ Fragmentation
  - ☑ Re-assembling fragmented messages
  - ☐ Periodic clean-up of "old" fragments
- Socialist Millionaire's Protocol:
  - ☑ OTRv2/OTRv3
  - ☑ OTRv4
- Client and PreKey Profiles:
  - ☑ Client Profile support
  - ☐ PreKey Profile support
- Extra Symmetric Key support:
  - ☑ OTRv3
  - ☑ OTRv4
- API support:
  - ☐ Verify if API still fully suitable for clients to adopt.
  - ☐ Ability to import/export DSA and EdDSA key pairs, such that `ClientProfile`s can be persisted/restored.
  - ☐ `OtrKeyManager` was removed. Evaluate whether this is a problem for adopters. (I prefer to leave it out or put it in its own repository.)
- Misc
  - ☑ Set flag `IGNORE_UNREADABLE` also for OTRv3 DISCONNECT and all SMP messages.  
  _Although not explicitly document that this is necessary, it should not break any existing applications. This makes implementations of OTRv3 and OTRv4 more similar and promotes better behavior in general, being: the other party is not needlessly warned for (lost) messages that do not contain valuable content, i.e. they are part of the OTR process, but do not contain user content themselves._
  - ☐ Ability to define own, customized-per-network `phi` (shared session state) implementer addition for the `t` value calculation.  
  _Under consideration as part of the [OTRv4 client implementation recommendations](https://github.com/otrv4/otrv4-client-imp-recommendations/issues/3)._
  - ☐ Evaluate whether there really is an advantage to having `OtrEngineHost` calls specify a session instance. (Does it make sense to make the distinction?)
  - ☐ Evaluate cases of `OtrException` being thrown. Reduce number of cases where user has to handle an exception without there being a real resolution.

## Operational

- ☑ [PGP-signature verification maven plug-in](https://github.com/s4u/pgpverify-maven-plugin) for verification of dependencies and build plug-ins according to [predefined public keys mapping](../pgpkeys.list).
- Constant-time implementations:
  - ☑ MAC key comparison
  - ☑ Point and Scalar equality
  - ☑ Scalar value comparison
  - ☐ Ring signatures
- Cleaning up data:
  - ☑ Clearing byte-arrays containing sensitive material after use.
  - ☐ Clean up remaining message keys instances when transitioning away from encrypted message states.
  - ☐ Investigate effectiveness of clearing byte-arrays right before potential GC. (Maybe they are optimized away by JVM?)
- Verify OTR-protocol obligations of other party:
  - ☑ Verify that revealed MAC keys are present when expected. (I.e. is list of revealed MAC keys larger than 0 bytes?)
- In-memory representation of points and scalar values as byte-arrays:  
  _Note that we specifically refer to how the data is represented in memory. Operations require temporary conversion back and forth into an intermediate type._
  - ☑ Points kept as byte-arrays.
  - ☑ Scalar values kept as byte-arrays.
- Mathematical operations act on byte-array representations directly:  
  _See also [BearSSL big integer operations](https://www.bearssl.org/bigint.html)_
  - ☐ Scalar arithmetic operations
  - ☐ Point arithmetic operations
- Robustness
  - ☑ otr4j does not handle Error-type exceptions.  
  _If critical situations occur, for instance `OutOfMemoryError`, then all bets are off._
  - ☑ otr4j protects itself against `RuntimeException`s caused by callbacks into the host application.
  _Any occurrence of a `RuntimeException` is considered a bug on the host application side, and is caught and logged by otr4j._
- Concurrency:
  - ☑ Thread-safety with granularity of single master with its slave sessions.  
      Messages from different contacts can be processed concurrently. Messages from same contact different clients, are forced to sequential processing.
- Stability
  - ☐ Library in execution performance profiling.
  - ☐ Measure memory usage changes under long-term use/heavy load.
- OTRv3 - catching up:
  - ☐ In-memory representation for OTRv3.
  - ☐ Arithmetical operations on byte-arrays for OTRv2 and/or OTRv3 logic.

## Developmental

- ☑ Support Java 7+ to be compatible with Android.
- ☑ Encapsulate cryptographic material such that design facilitates appropriate use and maintenance.
- ☑ States, such as Message states, isolated as to prevent mistakes in mixing up variables and state management for different states.
- ☑ Strategically placed assertions to discover mistakes such as uninitialized/cleared byte-arrays.
- Tool support:
  - ☑ JSR-305 annotations for static analysis
  - ☑ Introduce compiler warnings failure at build-time
  - ☑ Introduce pmd analysis at build-time.
  - ☑ Introduce SpotBugs analysis at build-time
  - ☑ Introduce checkstyle at build-time to guard formatting/style
  - ☑ Introduce checkstyle _ImportControl_ module to guard the design structure
  - ☑ Introduce [ErrorProne](https://errorprone.info/docs/installation).
  - ☑ Introduce thread-safety verified by static analysis. ([ErrorProne: @GuardedBy annotation](https://github.com/google/error-prone/blob/master/annotations/src/main/java/com/google/errorprone/annotations/concurrent/GuardedBy.java))
  - ☑ Introduce [NullAway](https://github.com/uber/NullAway) for compile-time nullability checking. Defaults to _non-null_ by default.
  - ☐ Introduce [Animal sniffer](https://www.mojohaus.org/animal-sniffer/) build plug-in to verify that we do not break backwards-compatibility, once released.
  - ☐ Experiment with features of [Checker Framework](https://checkerframework.org).
  - ☒ spotbugs-annotations to support managing clean-up of cryptographic key material  
    _Google Error-Prone annotations prove to be more interesting. Adoption of those annotations has started already._
- ⌛ Issue: some tests fail on a rare occasion due to the `assert` checks that are embedded in the code. These tests should be updated to assume successful execution if input would trigger the assertion.
- ⌛ Significant amount of unit tests to accompany the library. (Currently: 1200+)
- ☐ Interoperability testing with other OTRv4 implementations.
