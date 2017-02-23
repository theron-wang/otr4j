/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.session.state.IncorrectStateException;

public interface Session {

    interface OTRv {

        int TWO = 2;
        int THREE = 3;

        Set<Integer> ALL = Collections.unmodifiableSet(
                new HashSet<Integer>(Arrays.asList(TWO, THREE)));
    }
    
    /* Methods that provide session information. */

    @Nonnull
    SessionID getSessionID();

    @Nonnull
    SessionStatus getSessionStatus();

    @Nonnull
    SessionStatus getSessionStatus(@Nonnull InstanceTag tag);

    @Nonnull
    OtrPolicy getSessionPolicy();

    int getProtocolVersion();

    @Nonnull
    InstanceTag getSenderInstanceTag();

    @Nonnull
    InstanceTag getReceiverInstanceTag();

    @Nonnull
    PublicKey getRemotePublicKey() throws IncorrectStateException;

    @Nonnull
    PublicKey getRemotePublicKey(@Nonnull InstanceTag tag) throws IncorrectStateException;

    @Nonnull
    List<Session> getInstances();

    /**
     * Get Extra Symmetric Key that is provided by OTRv3 based on the current Session Keys.
     *
     * @return Returns 256-bit (shared) secret that can be used to start an out-of-band confidential communication channel
     * @throws OtrException In case message status is not ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws OtrException;

    // Methods related to session use and control.

    void startSession() throws OtrException;

    @Nonnull
    Session getOutgoingInstance();

    boolean setOutgoingInstance(@Nonnull final InstanceTag tag);

    @Nonnull
    String[] transformSending(@Nonnull final String msgText) throws OtrException;

    @Nonnull
    String[] transformSending(@Nonnull String msgText, @Nonnull List<TLV> tlvs) throws OtrException;

    @Nullable
    String transformReceiving(@Nonnull String msgText) throws OtrException;

    void refreshSession() throws OtrException;

    void endSession() throws OtrException;

    // Methods related to zero-knowledge-based authentication.

    void initSmp(@Nullable String question, @Nonnull String secret) throws OtrException;

    void respondSmp(@Nonnull InstanceTag receiverTag, @Nullable String question, @Nonnull String secret) throws OtrException;

    void respondSmp(@Nullable String question, @Nonnull String secret) throws OtrException;

    void abortSmp() throws OtrException;

    boolean isSmpInProgress();

    // Methods related to registering OTR engine listeners.

    void addOtrEngineListener(@Nonnull OtrEngineListener l);

    void removeOtrEngineListener(@Nonnull OtrEngineListener l);
}
