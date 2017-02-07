/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrEngineListenerUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyUtil;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.ake.AuthContext;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.SmpTlvHandler;
import net.java.otr4j.session.state.State;
import net.java.otr4j.session.state.StatePlaintext;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO Define interface 'Session' that defines methods for general use, i.e. no intersecting methods with Context.
// TODO Make Session final, can only be done after having extracted an interface as we rely on mocking the Session implementation.
// TODO There's now a mix of checking by messageType and checking by instanceof to discover type of AKE message. This is probably not a good thing ...
public class Session implements Context, AuthContext {

    public interface OTRv {
        int TWO = 2;
        int THREE = 3;

        Set<Integer> ALL = Collections.unmodifiableSet(
                new HashSet<>(Arrays.asList(TWO, THREE)));
    }

    /**
     * Session state contains the currently active message state of the session.
     *
     * The message state, being plaintext, encrypted or finished, is the
     * instance that contains the logic concerning message handling for both
     * incoming and outgoing messages, and everything related to this message
     * state.
     *
     * Field is volatile to ensure that state changes are communicated as soon
     * as known they have been processed.
     */
    @Nonnull
    private volatile State sessionState;

    /**
     * State management for the AKE negotiation.
     */
    @Nonnull
    private volatile AuthState authState;

    /**
     * Slave sessions contain the mappings of instance tags to outgoing
     * sessions. In case of the master session, it is initialized with an empty
     * instance. In case of slaves the slaveSessions instance is initialized to
     * an (immutable) empty map.
     */
    @Nonnull
    private final Map<InstanceTag, Session> slaveSessions;

    /**
     * The currently selected slave session that will be used as the session
     * for outgoing messages.
     */
    @Nonnull
    private volatile Session outgoingSession;

    /**
     * Flag indicating whether this instance is a master session or a slave
     * session.
     */
    private final boolean masterSession;

    /**
     * The Engine Host instance. This is a reference to the host logic that uses
     * OTR. The reference is used to call back into the program logic in order
     * to query for parameters that are determined by the program logic.
     */
    private final OtrEngineHost host;

    private final Logger logger;

    /**
     * Offer status for whitespace-tagged message indicating OTR supported.
     */
    private OfferStatus offerStatus;

    /**
     * Sender instance tag.
     */
    private final InstanceTag senderTag;

    /**
     * Receiver instance tag.
     *
     * The receiver tag is only used in OTRv3. In case of OTRv2 the instance tag
     * will be empty.
     */
    private InstanceTag receiverTag;

    /**
     * Message assembler.
     */
    private final OtrAssembler assembler;

    /**
     * Message fragmenter.
     */
    private final OtrFragmenter fragmenter;

    /**
     * Secure random instance to be used for this Session. This single
     * SecureRandom instance is there to be shared among classes the classes in
     * this package in order to support this specific Session instance.
     *
     * The SecureRandom instance should not be shared between sessions.
     *
     * Note: Please ensure that an instance always exists, as it is also used by
     * other classes in the package.
     */
    private final SecureRandom secureRandom;

    /**
     * List of registered listeners.
     *
     * Synchronized access is required. This is currently managed in methods
     * accessing the list.
     */
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<>();

    public Session(@Nonnull final SessionID sessionID, @Nonnull final OtrEngineHost listener) {
        this(true, sessionID, listener, InstanceTag.ZERO_TAG, InstanceTag.ZERO_TAG,
                new SecureRandom(), StateInitial.instance());
    }

    /**
     * Constructor.
     *
     * @param masterSession True to construct master session, false for slave
     * session.
     * @param sessionID The session ID.
     * @param host OTR engine host instance.
     * @param senderTag The sender instance tag. The sender instance tag must be
     * provided. In case the ZERO tag is provided, we generate a random instance
     * tag for the sender.
     * @param receiverTag The receiver instance tag. The receiver instance tag
     * is allowed to be ZERO.
     * @param secureRandom The secure random instance.
     * @param authState The initial authentication state of this session
     * instance.
     */
    private Session(final boolean masterSession,
            @Nonnull final SessionID sessionID,
            @Nonnull final OtrEngineHost host,
            @Nonnull final InstanceTag senderTag,
            @Nonnull final InstanceTag receiverTag,
            @Nonnull final SecureRandom secureRandom,
            @Nonnull final AuthState authState) {
        this.masterSession = masterSession;
        this.secureRandom = Objects.requireNonNull(secureRandom);
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.sessionState = new StatePlaintext(sessionID);
        this.authState = Objects.requireNonNull(authState);
        this.host = Objects.requireNonNull(host);
        this.senderTag = senderTag == InstanceTag.ZERO_TAG ? InstanceTag.random(secureRandom) : senderTag;
        this.receiverTag = Objects.requireNonNull(receiverTag);
        this.offerStatus = OfferStatus.idle;
        // Master sessions use the map to manage slave sessions. Slave sessions do not use the map.
        slaveSessions = masterSession
                ? Collections.synchronizedMap(new HashMap<InstanceTag, Session>(0))
                : Collections.<InstanceTag, Session>emptyMap();
        outgoingSession = this;

        assembler = new OtrAssembler(this.senderTag);
        fragmenter = new OtrFragmenter(this, host);
    }

    /**
     * Expose secure random instance to other classes in the package.
     * Don't expose to public, though.
     *
     * @return Returns the Session's secure random instance.
     */
    @Override
    @Nonnull
    public SecureRandom secureRandom() {
        return this.secureRandom;
    }

    @Override
    @Nonnull
    public OtrFragmenter fragmenter() {
        return this.fragmenter;
    }

    @Override
    public void secure(@Nonnull final SecurityParameters s) throws InteractionFailedException {
        try {
            this.sessionState.secure(this, s);
        } catch (final OtrException ex) {
            throw new InteractionFailedException(ex);
        }
        if (this.sessionState.getStatus() != SessionStatus.ENCRYPTED) {
            throw new IllegalStateException("Session fails to transition to ENCRYPTED.");
        }
        logger.info("Session secured. Message state transitioned to ENCRYPTED.");
    }

    @Override
    public void setState(@Nonnull final State state) {
        this.sessionState = Objects.requireNonNull(state);
        OtrEngineListenerUtil.sessionStatusChanged(
                OtrEngineListenerUtil.duplicate(listeners), state.getSessionID());
    }

    @Override
    public void setState(@Nonnull final AuthState state) {
        logger.log(Level.FINEST, "Updating state from {0} to {1}.", new Object[]{this.authState, state});
        this.authState = Objects.requireNonNull(state);
    }

    @Nonnull
    @Override
    public KeyPair longTermKeyPair() {
        return this.host.getLocalKeyPair(this.sessionState.getSessionID());
    }

    @Override
    public int senderInstance() {
        return this.senderTag.getValue();
    }

    @Override
    public int receiverInstance() {
        return this.receiverTag.getValue();
    }

    public SessionStatus getSessionStatus() {
        return this.sessionState.getStatus();
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionState.getSessionID();
    }

    @Override
    public OtrEngineHost getHost() {
        return host;
    }

    @Override
    @Nonnull
    public OfferStatus getOfferStatus() {
        return this.offerStatus;
    }

    @Override
    public void setOfferStatusSent() {
        this.offerStatus = OfferStatus.sent;
    }

    @Nullable
    public String transformReceiving(@Nonnull String msgText) throws OtrException {

        // TODO consider if we should move this down after assembler processing. It is true that we do not allow any version of OTR, but at the same time, OTR is active and it may not make sense to NOT reconstruct a fragmented message even if we do not intend to process it. Would this result in weird messages that show up in the chat?
        final OtrPolicy policy = getSessionPolicy();
        if (!policy.viable()) {
            logger.warning("Policy does not allow any version of OTR, ignoring message.");
            return msgText;
        }

        try {
            msgText = assembler.accumulate(msgText);
            if (msgText == null) {
                return null; // Not a complete message (yet).
            }
        } catch (final UnknownInstanceException e) {
            // The fragment is not intended for us
            logger.finest(e.getMessage());
            OtrEngineHostUtil.messageFromAnotherInstanceReceived(this.host, this.sessionState.getSessionID());
            return null;
        } catch (final ProtocolException e) {
            logger.log(Level.WARNING, "An invalid message fragment was discarded.", e);
            return null;
        }

        final AbstractMessage m;
        try {
            m = SerializationUtils.toMessage(msgText);
            if (m == null) {
                return msgText;
            }
        } catch (final IOException e) {
            throw new OtrException("Invalid message.", e);
        }

        if (m.messageType != AbstractMessage.MESSAGE_PLAINTEXT) {
            offerStatus = OfferStatus.accepted;
        } else if (offerStatus == OfferStatus.sent) {
            offerStatus = OfferStatus.rejected;
        }

        if (m instanceof AbstractEncodedMessage && masterSession) {

            final AbstractEncodedMessage encodedM = (AbstractEncodedMessage) m;

            if (encodedM.protocolVersion == OTRv.THREE) {

                if (encodedM.receiverInstanceTag != this.senderTag.getValue()
                        && !(encodedM.messageType == AbstractEncodedMessage.MESSAGE_DH_COMMIT
                        && encodedM.receiverInstanceTag == 0)) {

                    // The message is not intended for us. Discarding...
                    logger.finest("Received an encoded message with receiver instance tag"
                            + " that is different from ours, ignore this message");
                    OtrEngineHostUtil.messageFromAnotherInstanceReceived(this.host, this.sessionState.getSessionID());
                    return null;
                }

                if (encodedM.senderInstanceTag != this.receiverTag.getValue()
                        && this.receiverTag.getValue() != 0) {

                    /*
                     * Message is intended for us but is coming from a different
                     * instance. We relay this message to the appropriate
                     * session for transforming.
                     */

                    logger.finest("Received an encoded message from a different instance. Our buddy"
                            +
                            "may be logged from multiple locations.");

                    final InstanceTag newReceiverTag = new InstanceTag(encodedM.senderInstanceTag);
                    synchronized (slaveSessions) {

                        if (!slaveSessions.containsKey(newReceiverTag)) {

                            // construct a new slave session based on an
                            // existing AuthContext, if it exists.
                            final Session session
                                    = new Session(false,
                                            this.sessionState.getSessionID(),
                                            this.host,
                                            this.senderTag,
                                            newReceiverTag,
                                            this.secureRandom,
                                            encodedM.messageType == AbstractEncodedMessage.MESSAGE_DHKEY
                                                    ? this.authState : StateInitial.instance());
                            
                            session.addOtrEngineListener(new OtrEngineListener() {

                                @Override
                                public void sessionStatusChanged(final SessionID sessionID) {
                                    OtrEngineListenerUtil.sessionStatusChanged(
                                            OtrEngineListenerUtil.duplicate(listeners), sessionID);
                                }

                                @Override
                                public void multipleInstancesDetected(final SessionID sessionID) {
                                }

                                @Override
                                public void outgoingSessionChanged(final SessionID sessionID) {
                                }
                            });

                            slaveSessions.put(newReceiverTag, session);

                            OtrEngineHostUtil.multipleInstancesDetected(this.host, this.sessionState.getSessionID());
                            OtrEngineListenerUtil.multipleInstancesDetected(
                                    OtrEngineListenerUtil.duplicate(listeners), this.sessionState.getSessionID());
                        }
                    }
                    return slaveSessions.get(newReceiverTag).transformReceiving(msgText);
                }
            }
        }

        logger.log(Level.INFO, "Received message with type {0}", m.messageType);
        switch (m.messageType) {
            case AbstractEncodedMessage.MESSAGE_DATA:
                return handleDataMessage((DataMessage) m);
            case AbstractMessage.MESSAGE_ERROR:
                handleErrorMessage((ErrorMessage) m);
                return null;
            case AbstractMessage.MESSAGE_PLAINTEXT:
                return handlePlainTextMessage((PlainTextMessage) m);
            case AbstractMessage.MESSAGE_QUERY:
                handleQueryMessage((QueryMessage) m);
                return null;
            case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
            case AbstractEncodedMessage.MESSAGE_DHKEY:
            case AbstractEncodedMessage.MESSAGE_REVEALSIG:
            case AbstractEncodedMessage.MESSAGE_SIGNATURE:
                final AbstractEncodedMessage reply = handleAKEMessage((AbstractEncodedMessage) m);
                if (reply != null) {
                    injectMessage(reply);
                }
                return null;
            // Unknown message type:
            default:
                // TODO consider if we want this or a checked exception. This will have issues when an unknown type is used that this client simply doesn't support, but doesn't really hurt the existing converstaion.
                throw new UnsupportedOperationException(
                        "Received an unknown message type.");
        }
    }

    private void handleQueryMessage(@Nonnull final QueryMessage queryMessage)
            throws OtrException {
        final SessionID sessionId = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received a query message from {1} through {2}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});

        final OtrPolicy policy = getSessionPolicy();
        if (queryMessage.versions.contains(OTRv.THREE) && policy.getAllowV3()) {
            logger.finest("Query message with V3 support found.");
            final DHCommitMessage dhCommit = respondAuth(OTRv.THREE);
            if (masterSession) {
                synchronized (slaveSessions) {
                    for (final Session session : slaveSessions.values()) {
                        session.authState = this.authState;
                    }
                }
            }
            injectMessage(dhCommit);
        } else if (queryMessage.versions.contains(OTRv.TWO) && policy.getAllowV2()) {
            logger.finest("Query message with V2 support found.");
            final DHCommitMessage dhCommit = respondAuth(OTRv.TWO);
            logger.finest("Sending D-H Commit Message");
            injectMessage(dhCommit);
        } else {
            logger.info("Query message received, but none of the versions are useful. They are either excluded by policy or by lack of support.");
        }
    }

    private void handleErrorMessage(@Nonnull final ErrorMessage errorMessage)
            throws OtrException {
        final SessionID sessionId = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received an error message from {1} through {2}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});
        this.sessionState.handleErrorMessage(this, errorMessage);
    }

    @Nullable
    private String handleDataMessage(@Nonnull final DataMessage data) throws OtrException {
        final SessionID sessionId = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received a data message from {1}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID()});
        return this.sessionState.handleDataMessage(this, data);
    }

    @Override
    public void injectMessage(@Nonnull final AbstractMessage m) throws OtrException {
        String msg = SerializationUtils.toString(m);
        final SessionID sessionId = this.sessionState.getSessionID();
        if (m instanceof QueryMessage) {
            String fallback = OtrEngineHostUtil.getFallbackMessage(this.host,
                    sessionId);
            if (fallback == null || fallback.isEmpty()) {
                fallback = SerializationConstants.DEFAULT_FALLBACK_MESSAGE;
            }
            msg += fallback;
        }

        if (SerializationUtils.otrEncoded(msg)) {
            // Content is OTR encoded, so we are allowed to partition.
            final String[] fragments;
            try {
                fragments = this.fragmenter.fragment(msg);
                for (final String fragment : fragments) {
                    this.host.injectMessage(sessionId, fragment);
                }
            } catch (final IOException e) {
                logger.warning("Failed to fragment message according to provided instructions.");
                throw new OtrException(e);
            }
        } else {
            this.host.injectMessage(sessionId, msg);
        }
    }

    private String handlePlainTextMessage(@Nonnull final PlainTextMessage plainTextMessage)
            throws OtrException {
        final SessionID sessionId = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received a plaintext message from {1} through {2}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});
        final String messagetext = this.sessionState.handlePlainTextMessage(this, plainTextMessage);
        if (plainTextMessage.versions.isEmpty()) {
            logger.finest("Received plaintext message without the whitespace tag.");
        } else {
            logger.finest("Received plaintext message with the whitespace tag.");
            handleWhitespaceTag(plainTextMessage);
        }
        return messagetext;
    }

    private void handleWhitespaceTag(@Nonnull final PlainTextMessage plainTextMessage) {
        final OtrPolicy policy = getSessionPolicy();
        if (!policy.getWhitespaceStartAKE()) {
            // no policy w.r.t. starting AKE on whitespace tag
            return;
        }
        logger.finest("WHITESPACE_START_AKE is set");
        if (plainTextMessage.versions.contains(Session.OTRv.THREE)
                && policy.getAllowV3()) {
            logger.finest("V3 tag found.");
            try {
                final DHCommitMessage dhCommit = respondAuth(Session.OTRv.THREE);
                if (masterSession) {
                    synchronized (slaveSessions) {
                        for (final Session session : slaveSessions.values()) {
                            session.authState = this.authState;
                        }
                    }
                }
                logger.finest("Sending D-H Commit Message");
                injectMessage(dhCommit);
            } catch (final OtrException e) {
                logger.log(Level.WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv3)", e);
            }
        } else if (plainTextMessage.versions.contains(Session.OTRv.TWO)
                && policy.getAllowV2()) {
            logger.finest("V2 tag found.");
            try {
                final DHCommitMessage dhCommit = respondAuth(Session.OTRv.TWO);
                logger.finest("Sending D-H Commit Message");
                injectMessage(dhCommit);
            } catch (final OtrException e) {
                logger.log(Level.WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv2)", e);
            }
        } else {
            logger.info("Message with whitespace tags received, but none of the tags are useful. They are either excluded by policy or by lack of support.");
        }
    }

    @Nullable
    private AbstractEncodedMessage handleAKEMessage(@Nonnull final AbstractEncodedMessage m) {
        final SessionID sessionID = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received a signature message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        final OtrPolicy policy = getSessionPolicy();
        if (m.protocolVersion == OTRv.TWO && !policy.getAllowV2()) {
            logger.finest("If ALLOW_V2 is not set, ignore this message.");
            return null;
        }
        if (m.protocolVersion == OTRv.THREE) {
            if (!policy.getAllowV3()) {
                logger.finest("ALLOW_V3 is not set, ignore this message.");
                return null;
            }
            if (m.receiverInstanceTag == 0 && !(m instanceof DHCommitMessage)) {
                // only allow receiverInstanceTag == 0 for D-H Commit messages.
                // These messages are the only messages that can be sent without
                // a receiver tag as these messages initiate communication. Any
                // other (encoded) message already contains the receiver
                // instance tag to indicate for which exact client the message
                // is intended.
                logger.finest("Received a AKE message other than DH Commit with "
                        + "receiver instance tag of 0.");
                return null;
            }
            if (m.receiverInstanceTag != 0 && this.senderTag.getValue() != m.receiverInstanceTag) {
                logger.finest("Received a AKE message with receiver instance tag"
                        + " that is different from ours, ignore this message");
                return null;
            }
        }

        // Verify that we received an AKE message using the previously agreed
        // upon protocol version. Exception to this rule for DH Commit message,
        // as this message initiates a new AKE negotiation and thus proposes a
        // new protocol version corresponding to the message's intention.
        if (m.messageType != AbstractEncodedMessage.MESSAGE_DH_COMMIT
                && m.protocolVersion != this.authState.getVersion()) {
            logger.log(Level.INFO, "AKE message containing unexpected protocol version encountered. ({0} instead of {1}.) Ignoring.",
                    new Object[]{m.protocolVersion, this.authState.getVersion()});
            return null;
        }

        // Right now, we assume that once we get to this point, the protocol
        // version in the received message is accurate. Therefore we can decide
        // based on this value what instance tag to set/update.
        this.receiverTag = m.protocolVersion == OTRv.TWO ? InstanceTag.ZERO_TAG : new InstanceTag(m.senderInstanceTag);
        try {
            return this.authState.handle(this, m);
        } catch (final IOException ex) {
            logger.log(Level.FINEST, "Ignoring message. Bad message content / incomplete message received.", ex);
            return null;
        } catch (final OtrCryptoException ex) {
            logger.log(Level.FINEST, "Ignoring message. Exception while processing message, likely due to verification failure.", ex);
            return null;
        } catch (final InteractionFailedException ex) {
            logger.log(Level.WARNING, "Failed to transition to ENCRYPTED message state.", ex);
            return null;
        }
    }

    @Nonnull
    public String[] transformSending(@Nonnull final String msgText)
            throws OtrException {
        return this.transformSending(msgText, Collections.<TLV>emptyList());
    }

    /**
     * Transform message to be sent to content that is sendable over the IM
     * network.
     *
     * @param msgText the (normal) message content
     * @param tlvs TLV items (must not be null, may be an empty list)
     * @return Returns the array of messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
    @Nonnull
    public String[] transformSending(@Nullable String msgText, @Nullable List<TLV> tlvs)
            throws OtrException {
        if (masterSession && outgoingSession != this && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.transformSending(msgText, tlvs);
        }
        if (msgText == null) {
            msgText = "";
        }
        if (tlvs == null) {
            tlvs = Collections.<TLV>emptyList();
        }
        return this.sessionState.transformSending(this, msgText, tlvs);
    }

    public void startSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.startSession();
            return;
        }
        if (this.getSessionStatus() == SessionStatus.ENCRYPTED) {
            logger.fine("startSession was called, however an encrypted session is already established.");
            return;
        }
        startAuth();
    }

    public void endSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.endSession();
            return;
        }
        this.sessionState.end(this);
    }

    public void refreshSession() throws OtrException {
        this.endSession();
        this.startSession();
    }

    public PublicKey getRemotePublicKey() throws State.IncorrectStateException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.getRemotePublicKey();
        }
        return this.sessionState.getRemotePublicKey();
    }

    public void addOtrEngineListener(@Nonnull OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    public void removeOtrEngineListener(@Nonnull OtrEngineListener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }

    @Override
    public OtrPolicy getSessionPolicy() {
        return this.host.getSessionPolicy(this.sessionState.getSessionID());
    }

    public KeyPair getLocalKeyPair() {
        return this.host.getLocalKeyPair(this.sessionState.getSessionID());
    }

    @Override
    public InstanceTag getSenderInstanceTag() {
        return senderTag;
    }

    @Override
    public InstanceTag getReceiverInstanceTag() {
        return receiverTag;
    }

    @Override
    public int getProtocolVersion() {
        // FIXME extend to use ENCRYPTED message state's protocol version too? Do we still need this? Or query at AuthContext? It's a derived value based on the current (or previously completed?) AKE conversation.
        return this.authState.getVersion();
    }

    public List<Session> getInstances() {
        final List<Session> result = new ArrayList<>();
        result.add(this);
        result.addAll(slaveSessions.values());
        return result;
    }

    public boolean setOutgoingInstance(@Nonnull final InstanceTag tag) {
        if (!masterSession) {
            // Only master session can set the outgoing session.
            return false;
        }
        final SessionID sessionId = this.sessionState.getSessionID();
        if (tag.equals(this.receiverTag)) {
            outgoingSession = this;
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionId);
            return true;
        }
        final Session newActiveSession = slaveSessions.get(tag);
        if (newActiveSession == null) {
            outgoingSession = this;
            return false;
        } else {
            outgoingSession = newActiveSession;
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionId);
            return true;
        }
    }

    @Nonnull
    public SessionStatus getSessionStatus(@Nonnull final InstanceTag tag) {
        if (tag.equals(this.receiverTag)) {
            return this.sessionState.getStatus();
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave == null ? this.sessionState.getStatus()
                    : slave.getSessionStatus();
        }
    }

    @Nonnull
    public PublicKey getRemotePublicKey(@Nonnull final InstanceTag tag) throws State.IncorrectStateException {
        if (tag.equals(this.receiverTag)) {
            return this.sessionState.getRemotePublicKey();
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave == null ? this.sessionState.getRemotePublicKey()
                    : slave.getRemotePublicKey();
        }
    }

    public Session getOutgoingInstance() {
        return outgoingSession;
    }

    @Override
    public void startAuth() throws OtrException {
        logger.finest("Starting Authenticated Key Exchange, sending query message");
        final OtrPolicy policy = this.getSessionPolicy();
        final Set<Integer> allowedVersions = OtrPolicyUtil.allowedVersions(policy);
        if (allowedVersions.isEmpty()) {
            throw new IllegalStateException("Current OTR policy declines all supported versions of OTR. There is no way to start an OTR session that complies with the policy.");
        }
        injectMessage(new QueryMessage(allowedVersions));
    }

    public DHCommitMessage respondAuth(final int version) throws OtrException {
        if (!OTRv.ALL.contains(version)) {
            throw new OtrException("Only allowed versions are: 2, 3");
        }
        logger.finest("Responding to Query Message with D-H Commit message.");
        return this.authState.initiate(this, version);
    }

    public void initSmp(@Nullable final String question, @Nonnull final String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == Session.OTRv.THREE) {
            outgoingSession.initSmp(question, secret);
            return;
        }
        final SmpTlvHandler handler = this.sessionState.getSmpTlvHandler();
        final List<TLV> tlvs = handler.initRespondSmp(question, secret, true);
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            this.host.injectMessage(this.sessionState.getSessionID(), part);
        }
    }

    public void respondSmp(@Nonnull final InstanceTag receiverTag, @Nullable final String question, @Nonnull final String secret)
            throws OtrException
    {
        if (receiverTag.equals(this.receiverTag)) {
            respondSmp(question, secret);
            return;
        }
        final Session slave = slaveSessions.get(receiverTag);
        if (slave != null) {
            slave.respondSmp(question, secret);
        } else {
            respondSmp(question, secret);
        }
    }

    public void respondSmp(@Nullable final String question, @Nonnull final String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == Session.OTRv.THREE) {
            outgoingSession.respondSmp(question, secret);
            return;
        }
        final List<TLV> tlvs = this.sessionState.getSmpTlvHandler().initRespondSmp(question, secret, false);
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            this.host.injectMessage(this.sessionState.getSessionID(), part);
        }
    }

    public void abortSmp() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == Session.OTRv.THREE) {
            outgoingSession.abortSmp();
            return;
        }
        final List<TLV> tlvs = this.sessionState.getSmpTlvHandler().abortSmp();
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            this.host.injectMessage(this.sessionState.getSessionID(), part);
        }
    }

    public boolean isSmpInProgress() {
        if (this != outgoingSession && getProtocolVersion() == Session.OTRv.THREE) {
            return outgoingSession.isSmpInProgress();
        }
        try {
            return this.sessionState.getSmpTlvHandler().isSmpInProgress();
        } catch (final State.IncorrectStateException ex) {
            return false;
        }
    }

    /**
     * Acquire the extra symmetric key that can be derived from the session's
     * shared secret.
     *
     * This extra key can also be derived by your chat counterpart. This key
     * never needs to be communicated. TLV 8, that is described in otr v3 spec,
     * is used to inform your counterpart that he needs to start using the key.
     * He can derive the actual key for himself, so TLV 8 should NEVER contain
     * this symmetric key data.
     *
     * @return Returns the extra symmetric key.
     * @throws OtrException In case the message state is not ENCRYPTED, there
     * exists no extra symmetric key to return.
     */
    @Nonnull
    public byte[] getExtraSymmetricKey() throws OtrException {
        return this.sessionState.getExtraSymmetricKey();
    }
}
