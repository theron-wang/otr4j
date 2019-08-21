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
import javax.annotation.Nullable;

/**
 * SMP facilities of OTR engine host.
 *
 * We intentionally define a subset of all available OTR Engine Host methods for
 * use by the SMP "subsystem" to avoid abusing parts of the callback mechanism
 * that should only be used in certain places, such as the over-all session
 * implementation.
 *
 * @author Danny van Heumen
 */
public interface SmpEngineHost {

    /**
     * Signal Engine Host to ask user for answer to the question provided by the
     * other party in the authentication session.
     *
     * @param sessionID the session ID
     * @param receiverTag the receiver instance tag
     * @param question the question to be asked to the user by the Engine Host
     */
    void askForSecret(SessionID sessionID, InstanceTag receiverTag, @Nullable String question);

    /**
     * Request local fingerprint in raw byte form.
     *
     * @param sessionID the session ID
     * @return Returns the raw fingerprint bytes.
     */
    @Nonnull
    byte[] getLocalFingerprintRaw(SessionID sessionID);

    /**
     * Call Engine Host to inform of SMP error during authentication.
     *
     * @param sessionID the session ID
     * @param tlvType the TLV type
     * @param cheated status indicator for cheating (interruption before SMP
     * verification step was able to complete)
     */
    void smpError(SessionID sessionID, int tlvType, boolean cheated);

    /**
     * Call Engine Host to inform of SMP abort.
     *
     * @param sessionID the session ID
     */
    void smpAborted(SessionID sessionID);

    /**
     * When a remote user's key is verified via the Socialist Millionaire's
     * Protocol (SMP) shared passphrase or question/answer, this method will be
     * called upon successful completion of that process.
     *
     * @param sessionID of the session where the SMP happened.
     * @param fingerprint of the key to verify
     */
    void verify(SessionID sessionID, String fingerprint);

    /**
     * If the Socialist Millionaire's Protocol (SMP) process fails, then this
     * method will be called to make sure that the session is marked as
     * untrustworthy.
     *
     * @param sessionID of the session where the SMP happened.
     * @param fingerprint of the key to unverify
     */
    void unverify(SessionID sessionID, String fingerprint);
}
