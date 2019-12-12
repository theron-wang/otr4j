**NOTE**: *This version of otr4j is in active development for the adoption of the [OTRv4][OTRv4] specification that is being developed at this moment.*

The repository for otr4j OTRv4 development is [github.com/otr4j/otr4j][otr4j/otr4j].

# otr4j

This is a fork of the [original otr4j](https://github.com/jitsi/otr4j). The original otr4j started development as an GSoC 2009 project. A few years ago, a attempt was made to create a "community-friendly fork" of otr4j with the intention to lower the barrier for contribution: it is not required to sign a CLA. The original attempt never took off due to most of the original otr4j developers no longer focused on further development and improvement of otr4j.

This repository contains the community-friendly fork with the addition of significant refactoring effort and recently the addition of [OTRv4][OTRv4] support. As [OTRv4][OTRv4] is still in draft, the implementation of this otr4j implementation itself is not stable (or secure).

## Progress

Current work should be considered __at most__ _prototype-quality and guaranteed insecure._ The development follows the _master_ branch of [OTRv4], but may lag behind in areas that currently lack development focus.

__2019-10-28__ Due to third-party contributions made under dubious circumstances, i.e. possibly made during working time instead of personal time, some merges in the commit history have been redone. There are no longer any third-party contributions in the OTRv4 work. The [original master-branch content][original-master] is still available.

__Development stages__:

_Note: temporary dependency on [gitlab.com/cobratbq/joldilocks][joldilocks]: see bottom of README.md_

- ✔ Minimal working encryption (Interactive DAKE, message encryption/decryption, self-serving)  
  _a.k.a. "at least the bugs are symmetric in nature :-)"_
- ✔ Socialist Millionaire's Protocol for OTRv4.
- ✔ Migrate OTRv4 DAKE state machine into OTRv4 Message state machine.
- ⌛ Redesigned Double Ratchet algorithm.  
  _Requires update to the OTRv4 specification._
- ⌛ Migrate Ed448-Goldilocks and EdDSA implementation to Bouncy Castle.  
  _Requires additions to the BouncyCastle API, as certain necessary operations are not currently supplied._
  - ✔ EdDSA long-term keypair
  - ⌛ ECDH keypair
  - _ Ring Signatures
  - _ SMP for OTRv4
- _ Support for skipped messages, keeping track of skipped message keys.
- _ OTRv4 maintenance tasks (<s>session expiration timer</s>, <s>heartbeat timer></s>, refreshing client profile)
- _ Full implementation of "OTRv3-compatible" + "OTRv4 Interactive" use cases (including all FIXMEs)
  - _ Full review against the (finalized) OTRv4 spec.  
    _As the specification has been modified during implementation of support in otr4j, a full review against current spec is needed._
  - _ Stabilize, fix and then guard (AnimalSniffer) the public API offered by otr4j.
- _ Clean up OTRv2 support.
- _ Clean up remaining TODOs
- _ Review comments to spot out-of-date quotes from the spec. (Probably better to ignore or generalize.)
- _ Review and clean up logging statements. Ensure that no secret data is exposed through logging. Verify if log levels are reasonable.

Refer to the [__checklist with functional, operational and developmental details__][checklist] for further details.

## Architectural considerations

Architectural constraints that are respected in the design.

1. Correctness of protocol implementation.
1. Encapsulation of cryptographic material to prevent mistakes, misuse, excessive exposure.
1. Design that prevents or makes obvious programming errors.
1. Simplicity: restricted implementation with only as much complexity and abstraction as needed.

## Using otr4j

_Note: otr4j with OTRv4 support is not backwards-compatible with older releases. Although the API has not changed significantly, some restructuring has been performed and the interfaces extended to be able to support client requirements of OTRv4._

The easiest way to start adoption of this new version given an earlier implementation of otr4j is already in use:

1. Throw away existing imports and import types as _many of the existing types_ have moved to the `net.java.otr4j.api` package.
1. Extend your implementation of `net.java.otr4j.api.OtrEngineHost` with the additional methods that are now required.
1. Fix any other syntactic failures / build failures. The javadoc on the various methods should clearly describe the
   method's API and expectations. If this is not the case, file a bug as this should be expected.  
   _As there are new features and upgraded cryptographic primitives in OTRv4, upgrading will not be effortless. However
   it should be possible to do a basic implementation in a reasonable amount of time._  

To further secure access to _otr4j_ state:

- Use security manager and policy files to prevent reflective access to `net.java.otr4j.crypto` and subpackages:  
  The architectural constraint prescribes that all sensitive cryptographic material is concentrated in `net.java.otr4j.crypto`. Secrets are encapsulated, but reflection would still allow access and extraction of this sensitive data.

## Limitations

- _otr4j supports message lengths up to 2^31._  
  Message sizes in OTR are defined as 4-byte _unsigned_. Due to Java's signed integer types, this implementation currently uses a signed integer. Therefore, the highest bit of the message length is interpreted as sign bit. Lengths over 2^31 are unsupported.
- _otr4j assumes message injections onto the (chat) network always succeed._  
  It is expected that message injection always succeeds. There is no way to signal that it failed and otr4j does not have any countermeasures in case it fails. (This may be added as a feature, but is currently not under consideration.)

## Contributing / Help needed

Please open an issue to discuss contributions early. As OTRv4 is still in draft and work on otr4j is active, things might change quickly.

- Helping with implementation work:
  - See the [Functional/Operational/Developmental action points][checklist].
  - Look for `FIXME`/`TODO` in the code.
- Peer-reviewing (for correctness, security and improvements in general)  
  _Don't trust me. I have done most of the work, so you can contribute the fixes to make it more trustworthy._
- Integration into chat clients
  - adoption
  - feedback on the API from the user perspective

## Build support and code style

The code is built using maven. The build configuration fails on compiler warnings and performs several types of static analysis. Checkstyle verifies the coding style and the same checkstyle configuration file can be used to configure your IDE. Although this does not catch all potential issues, I hope it will serve to provide early feedback for code contributions.

In addition to syntactic correctness checking, we enforce javadoc for anything that is part of the public API: _public_ and _protected_ classes methods and fields. The rationale is that the user of otr4j should expect reasonable information on the logic its able to call. Although some javadoc may still be limited in usefulness, we should aim to use it to clarify everything the user should know in using otr4j.

## Setting up your IDE: IntelliJ IDEA

1. Load the otr4j `pom.xml` file as a maven module (project).
1. Load `codecheck/checkstyle.xml` as the code style in IntelliJ (you will need to have the Checkstyle plug-in installed)
1. ... (I'm not sure if anything else is needed, but I'll update when I find out.)

## Dependency on [joldilocks][joldilocks]

Due to initial lack of support for Ed448-Goldilocks, a _very_ basic, limited Java library was written to support Ed448-Goldilocks. This library is by no means production-ready, does not provide any of the operational requirements necessary for security purposes and is not even guaranteed to be functionally correct. It did however enable further implementation of otr4j. We aim to completely migrate away from _joldilocks_ for otr4j. At most, we may keep it as a second opinion in unit testing code. _joldilocks_ needs Java 9 to compile so this dependency also raises our minimum required Java version for otr4j.



[OTR]: https://otr.cypherpunks.ca/
[jitsi]: https://jitsi.org/
[OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
[OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
[OTRv4]: https://github.com/otrv4/otrv4
[otr4j/otr4j]: https://github.com/otr4j/otr4j
[joldilocks]: https://gitlab.com/cobratbq/joldilocks "A beginner-level (functional) implementation of Ed448-Goldilocks."
[original-master]: https://gitlab.com/cobratbq/otr4j/tree/original-master "The original master branch. Before the history rewrite occurred."
[checklist]: docs/checklist.md "Checklist with functional, operational and developmental requirements."