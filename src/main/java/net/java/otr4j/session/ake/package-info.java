/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for necessary hashing functions and ciphers.
 */
// TODO re-evaluate checked exceptions in OtrCryptoEngine and remove checked exceptions in case they communicate JVM-support related issues.
// TODO when to reliably check if protocol version matches during AKE process and for which message types? (e.g. always skip for DH commit messages?)
// TODO structurally handle verification/validation errors.
// TODO modify state implementations in such a way that it is impossible to use keys/random data without it being initialized.
// TODO verify that various message types do not allow invalid/illegal message contents.
// FIXME check that all unchecked exceptions are warranted as they are used.
// FIXME follow state transition path and make sure long-term keypair is only requested once, then passed on.
// TODO need/required to clear temporary bytearray data containing key information?
// FIXME check if we do appropriate state transitions (back to NONE) for failed validations.
// FIXME move similar logging statements into new AKE state implementation.
// FIXME verify that all message-state combinations are now handled
// FIXME verify all DH public keys before using them! (See 'verify' in OtrCryptoEngine.)
package net.java.otr4j.session.ake;
