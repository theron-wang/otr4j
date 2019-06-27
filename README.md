**NOTE**: *This version of otr4j is in active development for the adoption of the [OTRv4][OTRv4] specification that is being developed at this moment.*

The repository for otr4j OTRv4 development is [github.com/otr4j/otr4j][otr4j/otr4j].

# otr4j

This is a fork of the [original otr4j](https://github.com/jitsi/otr4j). The original otr4j started development as an GSoC 2009 project. A few years ago, a attempt was made to create a "community-friendly fork" of otr4j with the intention to lower the barrier for contribution: it is not required to sign a CLA. The original attempt never took off due to most of the original otr4j developers no longer focused on further development and improvement of otr4j.

This repository contains the community-friendly fork with the addition of significant refactoring effort and recently the addition of [OTRv4][OTRv4] support. As [OTRv4][OTRv4] is still in draft, the implementation of this otr4j implementation itself is not stable (or secure).

## Progress

__Status__: _In active development_  
Current work should be considered __at most__ _prototype-quality and guaranteed insecure._ The development follows the _master_ branch of [OTRv4], but may lag behind in areas that currently lack development focus.

Development stages:

_Note: temporary dependency on [github.com/otr4j/joldilocks][joldilocks]: see bottom of README.md_

- ✔ Minimal working encryption (Interactive DAKE, message encryption/decryption, self-serving)  
  _a.k.a. "at least the bugs are symmetric in nature :-)"_
- ✔ Socialist Millionaire's Protocol for OTRv4.
- ✔ Migrate OTRv4 DAKE state machine into OTRv4 Message state machine.
- ⌛ Redesigned Double Ratchet algorithm.
- ⌛ Migrate Ed448-Goldilocks and EdDSA implementation to Bouncy Castle.  
  _Requires additions to the BouncyCastle API, as certain necessary operations are not currently supplied._
  - ✔ EdDSA long-term keypair
  - ⌛ ECDH keypair
  - _ Ring Signatures
  - _ SMP for OTRv4
- _ Support for skipped messages, keeping track of skipped message keys.
- _ OTRv4 maintenance tasks
- _ Full implementation of "OTRv3-compatible" + "OTRv4 Interactive" use cases (including all FIXMEs)
  - _ Full review against the (finalized) OTRv4 spec.  
    _As the specification has been modified during implementation of support in otr4j, a full review against current spec is needed._
  - _ Stabilize, fix and then guard (AnimalSniffer) the public API offered by otr4j.
- _ Clean up OTRv2 support.
- _ Clean up remaining TODOs
- _ Review comments to spot out-of-date quotes from the spec. (Probably better to ignore or generalize.)
- _ Review and clean up logging statements. Ensure that no secret data is exposed through logging. Verify if log levels are reasonable.

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
  - Edd448-Goldilocks elliptic curve
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

- Constant-time implementations:
  - ☑ MAC key comparison
  - ☑ Point and Scalar equality
  - ☐ Scalar value comparison
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
- Stability
  - ☐ Profile library in execution.
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
  - ☐ Introduce [Animal sniffer](https://www.mojohaus.org/animal-sniffer/) build plug-in to verify that we do not break backwards-compatibility, once released.
  - ☐ Experiment with features of [Checker Framework](https://checkerframework.org).
  - ☒ spotbugs-annotations to support managing clean-up of cryptographic key material  
    _Google Error-Prone annotations prove to be more interesting. Adoption of those annotations has started already._
- ⌛ Issue: some tests fail on a rare occasion due to the `assert` checks that are embedded in the code. These tests should be updated to assume successful execution if input would trigger the assertion.
- ☐ Significant amount of unit tests to accompany the library. (Currently: 1200+)
- ☐ Interoperability testing with other OTRv4 implementations.

## Architectural considerations

Architectural constraints that are respected in the design.

1. Correctness of protocol implementation.
1. Encapsulation of cryptographic material to prevent mistakes, misuse, excessive exposure.
1. Design that prevents or makes obvious programming errors.
1. Simplicity: restricted implementation with only as much complexity and abstraction as needed.

# Using otr4j

_Note: otr4j with OTRv4 support is not backwards-compatible with older releases. Although the API has not changed significantly, some restructuring has been performed and the interfaces extended to be able to support client requirements of OTRv4._

The easiest way to start adoption of this new version given an earlier implementation of otr4j:

1. Throw away existing imports and import types as _many of the existing types_ have moved to the `net.java.otr4j.api` package.
1. Extend your implementation of `net.java.otr4j.api.OtrEngineHost` with the additional methods that are now required.
1. Fix any other syntactic failures / build failures. The javadoc on the various methods should clearly describe the
   method's API and expectations. If this is not the case, file a bug as this should be expected.  
   _As there are new features and upgraded cryptographic primitives in OTRv4, upgrading will not be effortless. However
   it should be possible to do a basic implementation in a reasonable amount of time._  

# Contributing / Help needed

Please open an issue to discuss contributions early. As OTRv4 is still in draft and work on otr4j is active, things might change quickly.

- Helping with implementation work:
  - See the Functional/Operational/Developmental action points above.
  - Look for `FIXME`/`TODO` in the code.
- Peer-reviewing (for correctness, security and improvements in general)  
  _Don't trust me. I have done most of the work, so you can contribute the fixes to make it trustworthy for you!_
- Integration into chat clients
  - adoption
  - feedback on the API from the user perspective

## Build support and code style

The code is built using maven. The build configuration fails on compiler warnings and performs several types of static analysis. Checkstyle verifies the coding style and the same checkstyle configuration file can be used to configure your IDE. Although this does not catch all potential issues, I hope it will serve to provide early feedback for code contributions.

In addition to syntactic correctness checking, we enforce javadoc for anything that is part of the *public* API: _public_ and _protected_ classes methods and fields. The rationale for this is that the user of otr4j should expect reasonable information on the logic its able to call. Although some javadoc may still be limited in usefulness, we should aim to use it to clarify everything the user should know in using otr4j.

## Setting up your IDE: IntelliJ IDEA

1. Load the otr4j `pom.xml` file as a maven module.
1. Load `codecheck/checkstyle.xml` as the code style in IntelliJ (you will need to have the Checkstyle plug-in installed)
1. ... (I'm not sure if anything else is needed, but I'll update when I find out.)

# Limitations

* _otr4j supports message lengths up to 2^31._  
  Message sizes in OTR are defined as 4-byte _unsigned_. Due to Java's signed integer types, this implementation currently uses a signed integer. Therefore, the highest bit of the message length is interpreted as sign bit. Lengths over 2^31 are unsupported.
* _otr4j assumes message injections onto the (chat) network always succeed._  
  It is expected that message injection always succeeds. There is no way to signal that it failed and otr4j does not have any countermeasures in case it fails. (This may be added as a feature, but is currently not under consideration.)

# Dependency on [joldilocks][joldilocks]

Due to initial lack of support for Ed448-Goldilocks, a _very_ basic, limited Java library was written to support Ed448-Goldilocks. This library is by no means production-ready, does not provide any of the operational requirements necessary for security purposes and is not even guaranteed to be functionally correct. It did however enable further implementation of otr4j. We aim to completely migrate away from _joldilocks_ for otr4j. At most, we may keep it as a second opinion in unit testing code. _joldilocks_ needs Java 9 to compile so this dependency also raises our minimum required Java version for otr4j.



[OTR]: https://otr.cypherpunks.ca/
[jitsi]: https://jitsi.org/
[OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
[OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
[OTRv4]: https://github.com/otrv4/otrv4
[otr4j/otr4j]: https://github.com/otr4j/otr4j
[joldilocks]: https://github.com/otr4j/joldilocks
