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
     * @param y the receiver's ECDH public key
     * @param b the receiver's DH public key
     * @param phi the shared session state (phi)
     * @throws ValidationException In case the message fails validation.
     */
    public static void validate(final AuthRMessage message, final ClientProfilePayload ourProfilePayload,
            final ClientProfile ourProfile, final ClientProfile theirProfile, final Point y, final BigInteger b,
            final byte[] phi) throws ValidationException {
        try {
            verifyECDHPublicKey(message.x);
            verifyDHPublicKey(message.a);
            verifyECDHPublicKey(message.firstECDHPublicKey);
            verifyDHPublicKey(message.firstDHPublicKey);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
        validateNotEquals(message.x, message.firstECDHPublicKey,
                "Different ECDH public keys expected for key exchange and first ratchet.");
        validateNotEquals(message.a, message.firstDHPublicKey,
                "Different DH public keys expected for key exchange and first ratchet.");
        validateEquals(message.senderTag, theirProfile.getInstanceTag(), "Sender instance tag does not match with owner instance tag in client profile.");
        final byte[] t = MysteriousT4.encode(AUTH_R, ourProfilePayload, message.clientProfile, y, message.x, b,
                message.a, phi);
        try {
            ringVerify(ourProfile.getForgingKey(), theirProfile.getLongTermPublicKey(), y, message.sigma, t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature failed verification.", e);
        }
    }
}
