/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

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
import net.java.otr4j.session.ake.Context;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.State;
import net.java.otr4j.session.ake.StateInitial;

/**
 * Authentication context.
 *
 * @author George Politis
 */
// TODO Consider removing AuthContext and merging contents into Session. There seems to be little value left in this class now that we have split off all the actual AKE negotiation and state management logic into the various State implementations.
public class AuthContext implements Context {

    public AuthContext(@Nonnull final Session session) {
        final SessionID sID = session.getSessionID();
        this.logger = Logger.getLogger(sID.getAccountID() + "-->" + sID.getUserID());
        this.session = session;
        this.state = StateInitial.instance();
        logger.finest("Construct new authentication state.");
    }

    /**
     * Special constructor for purpose of creating a new AuthContext instance
     * with values duplicated from the provided AuthContext instance.
     *
     * @param session The session instance.
     * @param other The other AuthContext instance.
     */
    public AuthContext(@Nonnull final Session session, @Nonnull final AuthContext other) {
        final SessionID sID = session.getSessionID();
        this.logger = Logger.getLogger(sID.getAccountID() + "-->" + sID.getUserID());
        this.session = Objects.requireNonNull(session);
        logger.finest("Copy-construct authentication state.");
        this.state = other.state;
    }

    private final Session session;

    private final Logger logger;

    private State state;

    @Override
    public void setState(@Nonnull final State state) {
        logger.log(Level.FINEST, "Updating state from {0} to {1}", new Object[]{this.state, state});
        this.state = Objects.requireNonNull(state);
    }

    @Override
    public void secure(@Nonnull final SecurityParameters params) throws InteractionFailedException {
        try {
            this.session.secure(params);
        } catch (final OtrException ex) {
            throw new InteractionFailedException(ex);
        }
        if (this.session.getSessionStatus() != SessionStatus.ENCRYPTED) {
            throw new IllegalStateException("Session fails to transition to ENCRYPTED.");
        }
        logger.info("Session secured. Message state transitioned to ENCRYPTED.");
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

    // TODO Fix this function to take into account the current message state.
    public int getVersion() {
        return this.state.getVersion();
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
    public final void reset(@Nonnull final AuthContext other) {
        logger.finest("Resetting authentication state.");
        this.state = other.state;
    }

    public void handleReceivingMessage(@Nonnull final AbstractMessage m) throws OtrException {
        logger.log(Level.INFO, "Received message with type {0}", m.messageType);
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
        } catch (final InteractionFailedException ex) {
            throw new OtrException("Failed to handle Signature message.", ex);
        } catch (final IOException ex) {
            throw new OtrException("Bad message received: failed to process full message.", ex);
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
        } catch (final InteractionFailedException ex) {
            throw new OtrException("Failed to handle Reveal Signature message.", ex);
        } catch (final IOException ex) {
            throw new OtrException("Bad message received: failed to process full message.", ex);
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
        } catch (final InteractionFailedException ex) {
            throw new OtrException("Failed to handle DH Key message.", ex);
        } catch (final IOException ex) {
            throw new OtrException("Bad message received: failed to process full message.", ex);
        }

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
        } catch (final InteractionFailedException ex) {
            throw new OtrException("Failed to handle DH Commit message.", ex);
        } catch (final IOException ex) {
            throw new OtrException("Bad message received: failed to process full message.", ex);
        }

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
        if (!OTRv.ALL.contains(version)) {
            throw new OtrException("Only allowed versions are: 2, 3");
        }
        logger.finest("Responding to Query Message with D-H Commit message.");
        return this.state.initiate(this, version);
    }

    // TODO consider if this is really the way we want to enable thorough testing/inspection.
    State getState() {
        return this.state;
    }
}
