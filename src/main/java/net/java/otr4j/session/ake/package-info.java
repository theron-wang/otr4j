/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// TODO verify that various message types do not allow invalid/illegal message contents.
// TODO need/required to clear temporary bytearray data containing key information? (AKE states)
// TODO consider not using InstanceTag type in this package and instead sticking with int values ... To improve reusability as stand-alone package.
// TODO should all states except for Initial (AUTHSTATE_NONE) have some kind of inherent time-out such that we cannot infinitely "stay" on a single state? (e.g. AWAITING_DHKEY in case of DH-Commit w/o receiver tag)
package net.java.otr4j.session.ake;
