/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;

/**
 * Session utilities.
 */
public final class Sessions {

    private Sessions() {
        // No need to instantiate utility class.
    }

    /**
     * Generate an identifier based on session data: session ID and receiver instance tag.
     *
     * @param session the session
     * @return Returns id for session.
     */
    @Nonnull
    public static String generateIdentifier(final Session session) {
        return session.getSessionID() + ", " + session.getReceiverInstanceTag().getValue();
    }
}
