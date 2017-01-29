/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// TODO re-evaluate checked exceptions in OtrCryptoEngine and remove checked exceptions in case they communicate JVM-support related issues.
// TODO when to reliably check if protocol version matches during AKE process and for which message types? (e.g. always skip for DH commit messages?)
// TODO structurally handle verification/validation errors.
// TODO modify state implementations in such a way that it is impossible to use keys/random data without it being initialized.
// TODO verify that various message types do not allow invalid/illegal message contents.
// TODO need/required to clear temporary bytearray data containing key information? (AKE states)
// TODO what to do with version mismatch, do we throw runtime exception or silently ignore?
package net.java.otr4j.session.ake;
