/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO In several places arrays exposed as public fields/through accessor methods which allows code to modify its contents. (Fixed for crypto constants, not for AES keys + MAC keys + CTR values, TLV values, etc.) (Detected by FindBugs.)
// TODO In the current implementation, we always query the host for the current session policy. What do we do if the policy changes during operation? Although not a big issue, it does make it possible to have some interesting unexpected state changes. Should we cache the policy for an encrypted session?
// TODO search for if == null throw patterns and replace with Objects.requireNonNull.
// TODO consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// TODO what's the status on reproducible builds of Java programs?
// TODO investigate usefulness of Java 9 module, maybe just as an experiment ...
/**
 * otr4j.
 */
package net.java.otr4j;
