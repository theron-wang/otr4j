/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// TODO verify that various message types do not allow invalid/illegal message contents.
// TODO need/required to clear temporary bytearray data containing key information? (AKE states)
// TODO consider not using InstanceTag type in this package and instead sticking with int values ... To improve reusability as stand-alone package.
package net.java.otr4j.session.ake;
