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

import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.Validators.validateEquals;

/**
 * Utility class for AuthIMessage.
 */
public final class AuthIMessages {

    private AuthIMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate an Auth-I message.
     *
     * @param message the Auth-I message to be validated
     * @param payloadAlice our client profile (non-validated, as payload)
     * @param profileAlice our client profile
     * @param payloadBob other party's client profile (as payload)
     * @param profileBob other party's client profile, validated
     * @param x ephemeral ECDH public key 'X'
     * @param y ephemeral ECDH public key 'Y'
     * @param a ephemeral DH public key 'A'
     * @param b ephemeral DH public key 'B'
     * @param phi shared session state (phi)
     * @throws ValidationException In case validation fails.
     */
    public static void validate(final AuthIMessage message, final ClientProfilePayload payloadAlice,
            final ClientProfile profileAlice, final ClientProfilePayload payloadBob, final ClientProfile profileBob,
            final Point x, final Point y, final BigInteger a, final BigInteger b, final byte[] phi)
            throws ValidationException {
        validateEquals(message.senderTag, profileBob.getInstanceTag(),
                "Sender instance tag does not match with owner instance tag in client profile.");
        // FIXME need to verify that message does not contain same points multiple times (i.e. not actually rotating)
        // We don't do extra verification of points here, as these have been verified upon receiving the Identity
        // message. This was the previous message that was sent. So we can assume points are trustworthy.
        final byte[] t = MysteriousT4.encode(AUTH_I, payloadBob, payloadAlice, y, x, b, a, phi);
        try {
            ringVerify(profileBob.getLongTermPublicKey(), profileAlice.getForgingKey(), x, message.sigma, t);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Ring signature verification failed.", e);
        }
    }
}
