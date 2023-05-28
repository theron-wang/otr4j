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
import static net.java.otr4j.messages.Validators.validateNotEquals;

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
     * @param message the AUTH_R message
     * @param ourProfilePayload our ClientProfile payload instance (non-validated)
     * @param ourProfile our Client Profile instance (the same as the payload, but validated)
     * @param theirProfile their Client Profile instance
     * @param senderAccountID the sender's account ID
     * @param receiverAccountID the Receiver's account ID
     * @param y the receiver's ECDH public key
     * @param b the receiver's DH public key
     * @param firstECDHPublicKey the receiver's (our) first ECDH public key after DAKE completes
     * @param firstDHPublicKey the receiver's (our) first DH public key after DAKE completes
     * @throws ValidationException In case the message fails validation.
     */
    public static void validate(final AuthRMessage message, final ClientProfilePayload ourProfilePayload,
            final ClientProfile ourProfile, final ClientProfile theirProfile, final String senderAccountID,
            final String receiverAccountID, final Point y, final BigInteger b, final Point firstECDHPublicKey,
            final BigInteger firstDHPublicKey) throws ValidationException {
        try {
            verifyECDHPublicKey(message.x);
            verifyDHPublicKey(message.a);
            verifyECDHPublicKey(message.firstECDHPublicKey);
            verifyDHPublicKey(message.firstDHPublicKey);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
        validateEquals(message.senderTag, theirProfile.getInstanceTag(), "Sender instance tag does not match with owner instance tag in client profile.");
        validateNotEquals(message.x, message.firstECDHPublicKey,
                "Different ECDH public keys expected for key exchange and first ratchet.");
        validateNotEquals(message.a, message.firstDHPublicKey,
                "Different DH public keys expected for key exchange and first ratchet.");
        final byte[] t = encode(AUTH_R, message.clientProfile, ourProfilePayload, message.x, y, message.a, b,
                message.firstECDHPublicKey, message.firstDHPublicKey, firstECDHPublicKey, firstDHPublicKey,
                message.senderTag, message.receiverTag, senderAccountID, receiverAccountID);
        try {
            ringVerify(ourProfile.getForgingKey(), theirProfile.getLongTermPublicKey(), y, message.sigma, t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature failed verification.", e);
        }
    }
}
