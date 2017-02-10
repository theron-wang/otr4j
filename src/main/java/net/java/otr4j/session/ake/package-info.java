/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// FIXME annotate parts of state implementations with comments from OTRv3 documentation for clarity/traceability.
// TODO verify that various message types do not allow invalid/illegal message contents.
// TODO need/required to clear temporary bytearray data containing key information? (AKE states)
package net.java.otr4j.session.ake;
