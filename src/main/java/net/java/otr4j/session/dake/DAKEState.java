/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.dake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.IdentityMessage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Interface for OTRv4 DAKE state instances.
 */
// FIXME need to check policy before initiating/handling protocol version 4 messages.
public interface DAKEState {

    /**
     * Initiate a new interactive DAKE.
     *
     * @param context the session as context
     * @param version the protocol version
     * @param receiverTag the receiver instance-tag
     * @return the IdentityMessage to send as DAKE initiation message
     */
    @Nonnull
    IdentityMessage initiate(DAKEContext context, Version version, InstanceTag receiverTag);

    /**
     * Handle an interactive DAKE message.
     *
     * @param context the session as context
     * @param message the incoming DAKE message
     * @return the response message to continue the DAKE
     */
    @Nonnull
    Result handle(DAKEContext context, AbstractEncodedMessage message);

    /**
     * Result of AKE state handling.
     */
    final class Result {
        /**
         * The response to send to the other party, if applicable.
         */
        @Nullable
        public final AbstractEncodedMessage response;

        /**
         * The security parameters on which to base the encrypted session.
         */
        @Nullable
        public final SecurityParameters4 params;

        Result() {
            this.response = null;
            this.params = null;
        }

        Result(@Nullable final AbstractEncodedMessage response, @Nullable final SecurityParameters4 params) {
            this.response = response;
            this.params = params;
        }
    }
}
