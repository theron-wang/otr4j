/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO consider upgrading Bouncy Castle libraries, needed?
// FUTURE consider extracting "domain" classes from 'session' package into separate package. This may solve significant part in cyclic dependencies between packages. Problem is that this will significantly break public API. We didn't care too much for now, but this may just be plain annoying.
// FUTURE could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
// FUTURE does it make sense to have some kind of plug-in system for OTR extensions?
// FUTURE consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// FUTURE what's the status on reproducible builds of Java programs?
// FUTURE investigate usefulness of Java 9 module, maybe just as an experiment ...
// FUTURE consider implementing OTRDATA (https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications)
/**
 * otr4j.
 */
package net.java.otr4j;
