/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import java.math.BigInteger;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.messages.Validators.validateEquals;

/**
 * Utility class for AuthRMessage. (Auth-R messages)
 */
public final class AuthRMessages {

    private AuthRMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate an AuthRMessage, using additional parameters to provide required data.
     *
     * @param message                    the AUTH_R message
     * @param ourClientProfilePayload    our ClientProfile payload instance (non-validated)
     * @param ourProfile                 our Client Profile instance (the same as the payload, but validated)
     * @param theirProfile               their Client Profile instance
     * @param senderAccountID            the sender's account ID
     * @param receiverAccountID          the Receiver's account ID
     * @param receiverECDHPublicKey      the receiver's ECDH public key
     * @param receiverDHPublicKey        the receiver's DH public key
     * @param receiverFirstECDHPublicKey the receiver's first ECDH public key after DAKE completes
     * @param receiverFirstDHPublicKey   the receiver's first DH public key after DAKE completes
     * @throws ValidationException In case the message fails validation.
     */
    public static void validate(final AuthRMessage message, final ClientProfilePayload ourClientProfilePayload,
            final ClientProfile ourProfile, final ClientProfile theirProfile, final String senderAccountID,
            final String receiverAccountID, final Point receiverECDHPublicKey, final BigInteger receiverDHPublicKey,
            final Point receiverFirstECDHPublicKey, final BigInteger receiverFirstDHPublicKey)
            throws ValidationException {
        try {
            verifyECDHPublicKey(message.x);
            verifyDHPublicKey(message.a);
            verifyECDHPublicKey(message.ourFirstECDHPublicKey);
            verifyDHPublicKey(message.ourFirstDHPublicKey);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
        validateEquals(message.senderTag, theirProfile.getInstanceTag(), "Sender instance tag does not match with owner instance tag in client profile.");
        final byte[] t = encode(AUTH_R, message.clientProfile, ourClientProfilePayload, message.x,
                receiverECDHPublicKey, message.a, receiverDHPublicKey, message.ourFirstECDHPublicKey,
                message.ourFirstDHPublicKey, receiverFirstECDHPublicKey, receiverFirstDHPublicKey,
                message.senderTag, message.receiverTag, senderAccountID, receiverAccountID);
        try {
            ringVerify(ourProfile.getForgingKey(), theirProfile.getLongTermPublicKey(), receiverECDHPublicKey,
                    message.sigma, t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature failed verification.", e);
        }
    }
}
