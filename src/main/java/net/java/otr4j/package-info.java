/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO In several places arrays exposed as public fields/through accessor methods which allows code to modify its contents. (Fixed for crypto constants, not for AES keys + MAC keys + CTR values, TLV values, etc.) (Detected by FindBugs.)
// TODO consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// TODO what's the status on reproducible builds of Java programs?
// TODO investigate usefulness of Java 9 module, maybe just as an experiment ...
// TODO check license header for all files
// TODO consider extracting "domain" classes from 'session' package into separate package. This may solve significant part in cyclic dependencies between packages. Problem is that this will significantly break public API. We didn't care too much for now, but this may just be plain annoying.
// TODO could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
/**
 * otr4j.
 */
package net.java.otr4j;
