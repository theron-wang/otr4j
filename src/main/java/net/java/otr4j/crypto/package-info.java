/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO Try to initialize all JCE components in static initializer such that we can be sure of suitable environment
//  - KeyAgreement.getInstance(KA_DH);
//  - KeyFactory.getInstance(KF_DH);
//  - Mac.getInstance(HMAC_SHA256);
//  - Mac.getInstance(HMAC_SHA1);
//  - MessageDigest.getInstance(MD_SHA256);
//  - MessageDigest.getInstance(MD_SHA1);
package net.java.otr4j.crypto;
