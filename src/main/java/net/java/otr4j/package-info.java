/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO Outstanding issue: In several places arrays exposed as public fields/through accessor methods which allows code to modify its contents. (Fixed for crypto constants, not for AES keys + MAC keys + CTR values, TLV values, etc.) (Detected by FindBugs.)
/**
 * otr4j.
 */
package net.java.otr4j;
