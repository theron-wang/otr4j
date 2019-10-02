/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
// TODO Review rule exclusions for maven-compiler-plugin, SpotBugs, pmd, ...
// NOTE OTRv3 does not document that SMP TLVs should have IGNORE_UNREADABLE flag set. So for now, we're not setting the flag for SMP TLVs.
// FIXME verify that description of process in https://github.com/otrv4/otrv4/blob/master/otrv4.md#receiving-an-identity-message - state=WAITING_AUTH_I is still accurate. Seems to talk about maintaining original message which cannot be because we deleted secure keys for our_ecdh_first and our_dh_first.
// TODO General questions on way-of-working for OTRv4:
//  * "Set their_ecdh as the 'Public ECDH key' from the message. Set their_dh as the 'Public DH Key' from the message, if it is not empty." are duplicate. Already included as part of Rotation instructions.
//  * OTRv4 ClientProfile verification does not clearly state what to do if DSA public key *without* transitional signature is found. (Drop DSA Public Key or reject profile completely.)
//  * Consider making an exception for the Identity message.
//    "Discard the message and optionally pass a warning to the participant if:
//    The recipient's own instance tag does not match the listed receiver instance tag."
//  * "Discard the (illegal) fragment if:" is missing criteria for index and total <= 65535.
//  * Nothing is said about case where sender and receiver tags are different in OTR-encoded message. (Should we consider a case where there is a difference illegal?)
//  * What to do if DH-Commit message is received as response to other client instance's query tag? (no receiver instance tag specified yet)
//  * Spec does not go into case "What to do if message from next/other ratchet arrives, but with index other than 0." (i.e. cannot decrypt, must reject.)
//    This is part of section "When you receive a Data Message:".
//  * Are or aren't active attacks part of the scope of OTRv4?
//    Section "Deletion of Stored Message Keys" describes measures against active malicious participants.
//  * Is there any documentation on how to behave if we are in an encrypted session, then get a new query message?
//    NO: sending query messages is not allowed. But then, what do we do if we still receive a query message?
//    - Expected behavior is to drop out of encrypted state and start new (D)AKE(?)
//    - We need to do something to protect user from sending intended-as-secure-message as plaintext accidentally due to losing a race (condition).
//  * What to do with queued messages? The obvious answer is: send them as soon as a private session has been
//    established. However, in practice it isn't that simple. A session can be established with multiple clients at a
//    time. Do we send the queued messages to the first established session instance? Or to all instances? If only to
//    one instance, there is a risk that we send it to the wrong instance. That is, a client is on and happens to be
//    first in establishing the connection, but it isn't the client that the user is currently working on. Then there is
//    a risk of exposing information to the wrong computer.
//  * Should we also reveal already gathered MAC codes upon ending encrypted session? Now it says to just forget about them, which seems unnecessary given that all the mechanisms are in place to reveal the remaining MAC codes. (https://github.com/otrv4/otrv4/blob/master/otrv4.md#revealing-mac-keys, https://github.com/otrv4/otrv4/issues/182)
//  * Should we (automatically) extend trust to the OTRv4 identity if we successfully establish a connection that contains a trusted (transitional) DSA long-term identity.
/**
 * otr4j.
 */
package net.java.otr4j;
