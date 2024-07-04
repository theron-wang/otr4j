/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;

import java.net.ProtocolException;
import java.time.Instant;
import java.util.logging.Logger;

import static java.util.logging.Level.FINE;

/**
 * ClientProfilePayloads provides utilities for ClientProfilePayload.
 */
public final class ClientProfilePayloads {

    private static final Logger LOGGER = Logger.getLogger(ClientProfilePayloads.class.getName());

    private ClientProfilePayloads() {
        // No need to instantiate.
    }

    /**
     * Check a client profile payload's internal consistency.
     *
     * @param payload the client profile payload as byte-array
     * @return Returns true iff valid.
     */
    @CheckReturnValue
    public static boolean check(final byte[] payload) {
        try {
            ClientProfilePayload.readFrom(new OtrInputStream(payload)).validate(Instant.now());
            return true;
        } catch (final ValidationException | ProtocolException | OtrCryptoException e) {
            LOGGER.log(FINE, "Failed client profile payload validation.", e);
            return false;
        }
    }
}
