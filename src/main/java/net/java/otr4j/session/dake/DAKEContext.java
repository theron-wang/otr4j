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
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.messages.ClientProfilePayload;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

/**
 * The context in which the DAKE operates. 
 */
public interface DAKEContext {

    /**
     * Acquire SecureRandom instance.
     *
     * @return SecureRandom instance
     */
    @Nonnull
    SecureRandom secureRandom();

    /**
     * Get sender tag.
     *
     * @return sender instance tag
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Get receiver tag.
     *
     * @return receiver instance tag
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * Update DAKE state in context.
     *
     * @param state new DAKE state
     */
    void setDAKEState(DAKEState state);

    /**
     * Get the OTR-encodable payload of the client profile.
     *
     * @return the OTR-encodable payload
     */
    @Nonnull
    ClientProfilePayload getClientProfilePayload();

    /**
     * Get ID of current session.
     *
     * @return session ID
     */
    @Nonnull
    SessionID getSessionID();

    /**
     * Access the long-term keypair for this DAKE session.
     * @return the long-term keypair
     */
    EdDSAKeyPair getLongTermKeyPair();
}
