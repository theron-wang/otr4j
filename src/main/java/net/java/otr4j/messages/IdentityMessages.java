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

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.messages.Validators.validateEquals;

/**
 * Utilities for identity messages.
 */
public final class IdentityMessages {

    private IdentityMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Validate identity message.
     *
     * @param message      The identity message.
     * @param theirProfile Their profile. The one shipped in the identity message. The message is passed in
     *                     independently such that we can avoid validating the profile multiple times.
     * @throws ValidationException Validation failure of parts of the Identity message.
     */
    public static void validate(final IdentityMessage message, final ClientProfile theirProfile)
            throws ValidationException {
        validateEquals(message.senderTag, theirProfile.getInstanceTag(), "Sender instance tag does not match with owner instance tag in client profile.");
        try {
            verifyECDHPublicKey(message.y);
            verifyDHPublicKey(message.b);
            verifyECDHPublicKey(message.ourFirstECDHPublicKey);
            verifyDHPublicKey(message.ourFirstDHPublicKey);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException | OtrCryptoException e) {
            throw new ValidationException("Illegal ephemeral public key.", e);
        }
    }
}
