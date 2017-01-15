/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyUtil;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import static net.java.otr4j.io.messages.AbstractMessage.checkCast;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureMessage;
import net.java.otr4j.session.Session.OTRv;
import net.java.otr4j.session.ake.AKEException;
import net.java.otr4j.session.ake.Context;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.State;

/**
 * @author George Politis
 */
public class AuthContext implements Context {
    // TODO consider converting this to a state machine. This enables better separation of state variables such that we only provide fields that are used in the current state.

    public AuthContext(final Session session) {
        SessionID sID = session.getSessionID();
        this.logger = Logger.getLogger(sID.getAccountID() + "-->" + sID.getUserID());
        this.session = session;
        logger.finest("Construct new authentication state.");
        this.reset(null);
    }

    /**
     * Special constructor for purpose of creating a new AuthContext instance
     * with values duplicated from the provided AuthContext instance.
     *
     * @param session The session instance.
     * @param other The other AuthContext instance.
     */
    public AuthContext(final Session session, final AuthContext other) {
        SessionID sID = session.getSessionID();
        this.logger = Logger.getLogger(sID.getAccountID() + "-->" + sID.getUserID());
        this.session = Objects.requireNonNull(session);
        logger.finest("Copy-construct authentication state.");
        this.reset(other);
    }

    private State state;

    // These parameters are initialized when generating D-H Commit Messages.
    // If the Session that this AuthContext belongs to is the 'master' session
    // then these parameters must be replicated to all slave session's auth
    // contexts.
    // FIXME how do we replicate this in the new State-pattern set-up? (My suspicion is that replication is not necessary at all. Even if you are in the middle of the AKE process, you want a unique DH keypair for each instance.)
    private KeyPair localDHKeyPair;

    private final Session session;

    private final Logger logger;

    @Override
    public void setState(@Nonnull final State state) {
        this.state = Objects.requireNonNull(state);
    }

    @Override
    public void secure(@Nonnull final SecurityParameters params) throws AKEException {
        try {
            this.session.secure(params);
        } catch (final OtrException ex) {
            throw new AKEException(ex);
        }
    }

    @Nonnull
    @Override
    public SecureRandom secureRandom() {
        return session.secureRandom();
    }

    @Nonnull
    @Override
    public KeyPair longTermKeyPair() {
        return session.getLocalKeyPair();
    }

    @Override
    public int senderInstance() {
        return session.getSenderInstanceTag().getValue();
    }

    @Override
    public int receiverInstance() {
        return session.getReceiverInstanceTag().getValue();
    }

    /**
     * Reset resets the state of the AuthContext.
     *
     * Reset is made final so that it cannot be overridden to make sure that
     * cleaning state does not accidentally fail.
     *
     * @param other Other AuthContext instance to use to duplicate state from
     * when resetting the state. This is optional. If null is provided, then we
     * will not copy state from other instance.
     */
    // TODO can we clean this method after refactoring to State pattern?
    public final void reset(@Nullable final AuthContext other) {
        logger.finest("Resetting authentication state.");

        if (other == null) {
            localDHKeyPair = null;
        } else {
            this.localDHKeyPair = other.localDHKeyPair;
        }
    }

    public void handleReceivingMessage(@Nonnull final AbstractMessage m) throws OtrException {

        switch (m.messageType) {
            case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
                handleDHCommitMessage(checkCast(DHCommitMessage.class, m));
                break;
            case AbstractEncodedMessage.MESSAGE_DHKEY:
                handleDHKeyMessage(checkCast(DHKeyMessage.class, m));
                break;
            case AbstractEncodedMessage.MESSAGE_REVEALSIG:
                handleRevealSignatureMessage(checkCast(RevealSignatureMessage.class, m));
                break;
            case AbstractEncodedMessage.MESSAGE_SIGNATURE:
                handleSignatureMessage(checkCast(SignatureMessage.class, m));
                break;
            default:
                throw new UnsupportedOperationException("Unsupported message type encountered: " + m.messageType);
        }
    }

    private void handleSignatureMessage(@Nonnull final SignatureMessage m) throws OtrException {
        final SessionID sessionID = session.getSessionID();
        logger.log(Level.FINEST, "{0} received a signature message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        if (m.protocolVersion == OTRv.TWO && !session.getSessionPolicy().getAllowV2()) {
            logger.finest("If ALLOW_V2 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE && !session.getSessionPolicy().getAllowV3()) {
            logger.finest("If ALLOW_V3 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE &&
                session.getSenderInstanceTag().getValue() != m.receiverInstanceTag) {
            logger.finest("Received a Signature Message with receiver instance tag"
                    + " that is different from ours, ignore this message");
            return;
        }

        final AbstractEncodedMessage reply;
        try {
            reply = this.state.handle(this, m);
        } catch (final AKEException ex) {
            throw new OtrException("Failed to handle Signature message.", ex);
        }
        if (reply != null) {
            session.injectMessage(reply);
        }
    }

    private void handleRevealSignatureMessage(@Nonnull final RevealSignatureMessage m)
            throws OtrException {
        final SessionID sessionID = session.getSessionID();
        logger.log(Level.FINEST, "{0} received a reveal signature message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});
        if (m.protocolVersion == OTRv.TWO && !session.getSessionPolicy().getAllowV2()) {
            logger.finest("If ALLOW_V2 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE && !session.getSessionPolicy().getAllowV3()) {
            logger.finest("If ALLOW_V3 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE &&
                session.getSenderInstanceTag().getValue() != m.receiverInstanceTag) {
            logger.finest("Received a Reveal Signature Message with receiver instance tag"
                    + " that is different from ours, ignore this message");
            return;
        }

        final AbstractEncodedMessage reply;
        try {
            reply = this.state.handle(this, m);
        } catch (final AKEException ex) {
            throw new OtrException("Failed to handle Reveal Signature message.", ex);
        }
        if (reply != null) {
            session.injectMessage(reply);
        }
    }

    private void handleDHKeyMessage(@Nonnull final DHKeyMessage m) throws OtrException {
        final SessionID sessionID = session.getSessionID();
        logger.log(Level.FINEST, "{0} received a D-H key message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        if (m.protocolVersion == OTRv.TWO && !session.getSessionPolicy().getAllowV2()) {
            logger.finest("If ALLOW_V2 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE && !session.getSessionPolicy().getAllowV3()) {
            logger.finest("If ALLOW_V3 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE
                && session.getSenderInstanceTag().getValue() != m.receiverInstanceTag) {
            logger.finest("Received a D-H Key Message with receiver instance tag"
                    + " that is different from ours, ignore this message");
            return;
        }

        session.setReceiverInstanceTag(new InstanceTag(m.senderInstanceTag));
        final AbstractEncodedMessage reply;
        try {
            reply = this.state.handle(this, m);
        } catch (final AKEException ex) {
            throw new OtrException("Failed to handle DH Key message.", ex);
        }
        // FIXME evaluate if we should handle case where reply is null.
        if (reply != null) {
            session.injectMessage(reply);
        }
    }

    private void handleDHCommitMessage(@Nonnull final DHCommitMessage m) throws OtrException {
        final SessionID sessionID = session.getSessionID();
        logger.log(Level.FINEST, "{0} received a D-H commit message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        // TODO move these checks to earlier in the handling process such that we can ignore uninteresting messages even before we get into concrete handling.
        if (m.protocolVersion == OTRv.TWO && !session.getSessionPolicy().getAllowV2()) {
            logger.finest("ALLOW_V2 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE && !session.getSessionPolicy().getAllowV3()) {
            logger.finest("ALLOW_V3 is not set, ignore this message.");
            return;
        } else if (m.protocolVersion == OTRv.THREE &&
                session.getSenderInstanceTag().getValue() != m.receiverInstanceTag &&
                m.receiverInstanceTag != 0) {

            logger.finest("Received a D-H commit message with receiver instance tag "
                    + "that is different from ours, ignore this message.");
            return;
        }

        session.setReceiverInstanceTag(new InstanceTag(m.senderInstanceTag));
        final AbstractEncodedMessage reply;
        try {
            reply = this.state.handle(this, m);
        } catch (final AKEException ex) {
            throw new OtrException("Failed to handle DH Commit message.", ex);
        }
        // FIXME evaluate if we should handle case where reply is null.
        if (reply != null) {
            session.injectMessage(reply);
        }
    }

    public void startAuth() throws OtrException {
        logger.finest("Starting Authenticated Key Exchange, sending query message");
        final OtrPolicy policy = session.getSessionPolicy();
        final Set<Integer> allowedVersions = OtrPolicyUtil.allowedVersions(policy);
        if (allowedVersions.isEmpty()) {
            throw new IllegalStateException("Current OTR policy declines all supported versions of OTR. There is no way to start an OTR session that complies with the policy.");
        }
        session.injectMessage(new QueryMessage(allowedVersions));
    }

    public DHCommitMessage respondAuth(final int version) throws OtrException {
        // FIXME replace with OTRv.ALL.contains(version)?
        if (version != OTRv.TWO && version != OTRv.THREE) {
            throw new OtrException(new Exception("Only allowed versions are: 2, 3"));
        }
        logger.finest("Responding to Query Message with D-H Commit message.");
        this.reset(null);
        session.setProtocolVersion(version);
        logger.finest("Generating D-H Commit.");
        return this.state.initiate(this, version);
    }

    // TODO consider if this is really the way we want to enable thorough testing/inspection.
    State getState() {
        return this.state;
    }
}
