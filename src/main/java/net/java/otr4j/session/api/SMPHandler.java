/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.api;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Handler for Socialist Millionaire's Protocol messages.
 * <p>
 * NOTE: this API should not be used by users of the otr4j library.
 */
public interface SMPHandler {

    /**
     * Initiate a new SMP negotiation.
     * <p>
     * NOTE: Initiating a new SMP negotiation after a previous SMP session has completed will obsolete the previous
     * result.
     *
     * @param question the question to be posed
     * @param answer   our answer to the question, to be used in the zero-knowledge proof
     * @return Returns the TLV that will request initiation of SMP.
     * @throws OtrException In case of issues while initiating SMP.
     */
    @Nonnull
    TLV initiate(final String question, final byte[] answer) throws OtrException;

    /**
     * Respond to SMP negotiation initiated by the other party.
     *
     * @param question the original question
     * @param answer   the our answer to the question
     * @return Returns TLV with response.
     * @throws OtrException In case of issues while responding.
     */
    @Nullable
    TLV respond(String question, byte[] answer) throws OtrException;

    /**
     * Check whether a SMP negotiation is in progress.
     *
     * @return Returns true iff negotiation is in progress.
     */
    @Nonnull
    SMPStatus getStatus();

    /**
     * Abort an existing SMP negotiation.
     *
     * @return TLV containing abort message.
     */
    @Nonnull
    TLV abort();

    /**
     * Test if TLV is for purpose of aborting SMP.
     *
     * @param tlv TLV
     * @return Returns true iff TLV is intended to signal aborting SMP.
     */
    @CheckReturnValue
    boolean smpAbortedTLV(TLV tlv);
}
