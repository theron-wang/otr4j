/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.crypto.OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES;

/**
 * Utility class for DataMessage4.
 */
public final class DataMessage4s {
    private static final Logger LOGGER = Logger.getLogger(DataMessage4s.class.getName());

    private DataMessage4s() {
        // No need to instantiate.
    }

    /**
     * Validate DataMessage4 instance.
     *
     * @param message the data message
     * @throws ProtocolException thrown if data message does not conform to specification.
     */
    // TODO create tests that verify appropriate expectations for DataMessage4, especially given need to handle before all data can be authenticated.
    public static void validate(final DataMessage4 message) throws ProtocolException {
        if ((message.i % 3 == 0) == (message.dhPublicKey == null)) {
            LOGGER.log(INFO, "Ratchet DH public key presence is not following specification: ratchet {0}, DH public key present: {1}",
                    new Object[]{message.i, message.dhPublicKey != null});
            throw new ProtocolException("Ratchet DH public key presence is not following specification.");
        }
        if (message.authenticator.length != AUTHENTICATOR_LENGTH_BYTES) {
            throw new ProtocolException("Message authenticator is illegal: bad size");
        }
        if (message.revealedMacs.length % AUTHENTICATOR_LENGTH_BYTES != 0) {
            assert false : "CHECK: Shouldn't there always be at least one MAC authenticator code to reveal?";
            LOGGER.warning("Expected other party to reveal recently used MAC codes, but no MAC codes are revealed! (This may be a bug in the other party's OTR implementation.)");
        }
        // TODO consider further validation actions for DataMessage4.
    }

    /**
     * Encode data message sections from provided DataMessage4 instance and return the byte-encoded representation.
     *
     * @param message the message instance
     * @return Returns the byte-encoded representation of the data message sections of the message.
     */
    @Nonnull
    public static byte[] encodeDataMessageSections(final DataMessage4 message) {
        final OtrOutputStream out = new OtrOutputStream();
        message.writeDataMessageSections(out);
        return out.toByteArray();
    }
}
