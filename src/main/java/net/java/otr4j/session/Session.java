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
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.ake.AuthContext;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.IncorrectStateException;
import net.java.otr4j.session.state.SmpTlvHandler;
import net.java.otr4j.session.state.State;
import net.java.otr4j.session.state.StatePlaintext;

/**
 * Implementation of the OTR session.
 *
 * <p>
 * otr4j Session supports OTRv2's single session as well as OTRv3's multiple
 * sessions, even simultaneously (at least in theory). Support is managed
 * through the concept of slave sessions. As OTRv2 does not recognize instance
 * tags, there can be only a single session. The master (non-slave) session will
 * represent the OTRv2 status. (As well as have an instance tag value of 0.)
 *
 * <p>
 * OTRv3 will establish all of its sessions in the {@link #slaveSessions} map.
 * The master session only functions as the inbound rendezvous point, but any
 * outbound activity as well as the session status itself is managed within a
 * (dedicated) slave session.
 *
 * <p>
 * There is an added complication in the fact that DH Commit message may be sent
 * with a receiver tag. At first instance, we have not yet communicated our
 * sender instance tag to our buddy. Therefore we (need to) allow DH Commit
 * messages to be sent without a receiver tag. As a consequence, we may receive
 * multiple DH Key messages in return, in case multiple client (instances) feel
 * inclined to respond. In the case where we send a DH Commit message without
 * receiver tag, we keep AKE state progression on the master session. This means
 * that the master session AKE state is set to AWAITING_DHKEY with appropriate
 * OTR protocol version. When receiving DH Key message(s) - for this particular
 * case - we copy AKE state to the (possibly newly created) slave sessions and
 * continue AKE message handling there.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO Define interface 'Session' that defines methods for general use, i.e. no intersecting methods with Context.
// TODO Make Session final, can only be done after having extracted an interface as we rely on mocking the Session implementation.
// TODO There's now a mix of checking by messageType and checking by instanceof to discover type of AKE message. This is probably not a good thing ...
// FIXME how does mix of OTRv3 (slave) sessions and OTRv2 session work with outgoing session? Will this lead to trouble in mix of ENCRYPTED and PLAINTEXT sessions?
// TODO can we define some sort of sanity check that ensures that ENCRYPTED message state is always correctly reflected, i.e. we always send messages ENCRYPTED if this appears so.
// TODO verify logic to ensure that we only attempt to start a new session if we are not ENCRYPTED (otherwise multiple clients might continue starting up new sessions to infinity)
// TODO should we attempt to verify/time-out AKE sessions? In case of DH Commit message w/o receiver tag, we keep AWAITING_DHKEY state in master and replicate to slave upon receiving DH Key message which includes their sender tag.
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

    @SuppressWarnings("NonConstantLogger")
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
     * will be zero-tag ({@link InstanceTag#ZERO_TAG}).
     */
    // TODO investigate how 'receiverTag' will function given mixed OTRv2 and OTRv3 sessions and multiple sessions in slaveSessions map. This might need to move to either slave sessions or session state.
    private final InstanceTag receiverTag;

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

    /**
     * Listener for propagating events from slave sessions to the listeners of
     * the master session. The same instance is reused for all slave sessions.
     */
    private final OtrEngineListener slaveSessionsListener = new OtrEngineListener() {

        @Override
        public void sessionStatusChanged(final SessionID sessionID) {
            OtrEngineListenerUtil.sessionStatusChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }

        @Override
        public void multipleInstancesDetected(final SessionID sessionID) {
            throw new IllegalStateException("Multiple instances should be detected in the master session. This event should never have happened.");
        }

        @Override
        public void outgoingSessionChanged(final SessionID sessionID) {
            throw new IllegalStateException("Outgoing session changes should be performed in the master session only. This event should never have happened.");
        }
    };

    /**
     * Constructor.
     *
     * @param sessionID The session ID
     * @param listener The OTR engine host listener.
     */
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
        // Master session uses the map to manage slave sessions. Slave sessions do not use the map.
        slaveSessions = masterSession
                ? Collections.synchronizedMap(new HashMap<InstanceTag, Session>(0))
                : Collections.<InstanceTag, Session>emptyMap();
        outgoingSession = this;
        // Initialize fragmented message support.
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

    public SessionStatus getSessionStatus() {
        return this.getSessionStatus(this.outgoingSession.receiverTag);
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

    // TODO potential "problem": In case we send DH-Commit and progress master session's AKE state, how long do we keep? OTR spec says that we should resend same DH-Commit message if receiving DH-Commit message from our buddy. This in itself is okay, but we might be "reusing" the same DH keypair for a long time if new client instances keep appearing. This is pretty much a non-issue ... just a weird edge case in the protocol in combination with this particular implementation.
    @Nullable
    public String transformReceiving(@Nonnull String msgText) throws OtrException {

        // TODO consider if we should move this down after assembler processing. It is true that we do not allow any version of OTR, but at the same time, OTR is active and it may not make sense to NOT reconstruct a fragmented message even if we do not intend to process it. Would this result in weird messages that show up in the chat? This allows receiving OTR encoded messages which will be displayed as plain text(?) Non-viable policy shouldn't be used to disable plugin support. This logic seems out of place.
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

        if (masterSession && m instanceof AbstractEncodedMessage
                && ((AbstractEncodedMessage) m).protocolVersion == OTRv.THREE) {
            // In case of OTRv3 delegate message processing to dedicated slave
            // session.
            final AbstractEncodedMessage encodedM = (AbstractEncodedMessage) m;

            if (encodedM.senderInstanceTag == 0) {
                // An encoded message without a sender instance tag is always bad.
                logger.warning("Encoded message is missing sender instance tag. Ignoring message.");
                return null;
            }

            if (encodedM.receiverInstanceTag != this.senderTag.getValue()
                    && !(encodedM instanceof DHCommitMessage && encodedM.receiverInstanceTag == 0)) {
                // The message is not intended for us. Discarding...
                logger.finest("Received an encoded message with receiver instance tag"
                        + " that is different from ours. Ignore this message.");
                OtrEngineHostUtil.messageFromAnotherInstanceReceived(this.host, this.sessionState.getSessionID());
                return null;
            }

            final InstanceTag messageSenderInstance = new InstanceTag(encodedM.senderInstanceTag);
            final Session session;
            if (encodedM instanceof DHCommitMessage) {
                // We are more flexible with processing the DH Commit
                // message as the message's receiver tag may be zero. It is
                // zero as we may not have announced our sender tag yet,
                // therefore they cannot include it in the DH commit
                // message.
                synchronized (slaveSessions) {
                    if (!slaveSessions.containsKey(messageSenderInstance)) {
                        final Session newSlaveSession = new Session(
                                false, this.sessionState.getSessionID(),
                                this.host, this.senderTag,
                                messageSenderInstance, this.secureRandom,
                                StateInitial.instance());
                        newSlaveSession.addOtrEngineListener(slaveSessionsListener);
                        slaveSessions.put(messageSenderInstance, newSlaveSession);
                    }
                    session = slaveSessions.get(messageSenderInstance);
                }
            } else if (encodedM instanceof DHKeyMessage) {
                // DH Key messages should be complete, however we may
                // receive multiple of these messages.
                synchronized (slaveSessions) {
                    if (!slaveSessions.containsKey(messageSenderInstance)) {
                        final Session newSlaveSession = new Session(
                                false, this.sessionState.getSessionID(),
                                this.host, this.senderTag,
                                messageSenderInstance, this.secureRandom,
                                this.authState);
                        newSlaveSession.addOtrEngineListener(slaveSessionsListener);
                        slaveSessions.put(messageSenderInstance, newSlaveSession);
                    }
                    session = slaveSessions.get(messageSenderInstance);
                }
                // Replicate AKE state to slave session for continuation of
                // AKE negotiation. We may receive multiple DH Key replies
                // as we may have sent a DH Commit message without
                // specifying a receiver tag, hence multiple clients may be
                // inclined to respond.
                session.authState = this.authState;
            } else {
                // Handle other encoded messages. By now we expect the
                // message sender's (receiver) tag to be known. If not we
                // consider this a bad message and ignore it.
                synchronized (slaveSessions) {
                    if (!slaveSessions.containsKey(messageSenderInstance)) {
                        logger.log(Level.INFO,
                                "Slave session instance missing for receiver tag: {0}. Our buddy may be logged in at multiple locations.",
                                messageSenderInstance.getValue());
                        OtrEngineHostUtil.multipleInstancesDetected(this.host, this.sessionState.getSessionID());
                        OtrEngineListenerUtil.multipleInstancesDetected(
                                OtrEngineListenerUtil.duplicate(listeners), this.sessionState.getSessionID());
                        final Session newSlaveSession = new Session(
                                false, this.sessionState.getSessionID(),
                                this.host, this.senderTag,
                                messageSenderInstance, this.secureRandom,
                                StateInitial.instance());
                        newSlaveSession.addOtrEngineListener(slaveSessionsListener);
                        slaveSessions.put(messageSenderInstance, newSlaveSession);
                    }
                    session = slaveSessions.get(messageSenderInstance);
                }
            }
            // FIXME work-around as we haven't found out yet when to switch outgoing instance.
            setOutgoingInstance(messageSenderInstance);
            return session.transformReceiving(msgText);
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
            default:
                // At this point, the message m has a known type, but support
                // was not implemented at this point in the code. This should be
                // considered a programming error. We should handle any known
                // message type gracefully. Unknown messages are caught earlier.
                throw new UnsupportedOperationException("Received an unknown message type.");
        }
    }

    private void handleQueryMessage(@Nonnull final QueryMessage queryMessage)
            throws OtrException {
        final SessionID sessionId = this.sessionState.getSessionID();
        logger.log(Level.FINEST, "{0} received a query message from {1} through {2}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});

        final OtrPolicy policy = getSessionPolicy();
        if (queryMessage.versions.contains(OTRv.THREE) && policy.getAllowV3()) {
            logger.finest("Query message with V3 support found. Sending D-H Commit Message.");
            injectMessage(respondAuth(OTRv.THREE, InstanceTag.ZERO_TAG));
        } else if (queryMessage.versions.contains(OTRv.TWO) && policy.getAllowV2()) {
            logger.finest("Query message with V2 support found. Sending D-H Commit Message.");
            injectMessage(respondAuth(OTRv.TWO, InstanceTag.ZERO_TAG));
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
            // TODO consider moving this somewhere else. It's a bit weird that we modify parts of a Query Message here.
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
        logger.finest("WHITESPACE_START_AKE is set, processing whitespace-tagged message.");
        if (plainTextMessage.versions.contains(Session.OTRv.THREE)
                && policy.getAllowV3()) {
            logger.finest("V3 tag found. Sending D-H Commit Message.");
            try {
                injectMessage(respondAuth(Session.OTRv.THREE, InstanceTag.ZERO_TAG));
            } catch (final OtrException e) {
                logger.log(Level.WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv3)", e);
            }
        } else if (plainTextMessage.versions.contains(Session.OTRv.TWO)
                && policy.getAllowV2()) {
            logger.finest("V2 tag found. Sending D-H Commit Message.");
            try {
                injectMessage(respondAuth(Session.OTRv.TWO, InstanceTag.ZERO_TAG));
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

        // Verify that policy allows handling message according to protocol version.
        final OtrPolicy policy = getSessionPolicy();
        if (m.protocolVersion == OTRv.TWO && !policy.getAllowV2()) {
            logger.finest("ALLOW_V2 is not set, ignore this message.");
            return null;
        }
        if (m.protocolVersion == OTRv.THREE && !policy.getAllowV3()) {
            logger.finest("ALLOW_V3 is not set, ignore this message.");
            return null;
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

    /**
     * Transform message to be sent to content that is sendable over the IM
     * network. Do not include any TLVs in the message.
     *
     * @param msgText the (normal) message content
     * @return Returns the (array of) messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
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
     * @return Returns the (array of) messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
    // TODO consider changing public API to not allow null list of TLVs and null msgText.
    @Nonnull
    public String[] transformSending(@Nullable String msgText, @Nullable List<TLV> tlvs)
            throws OtrException {
        if (masterSession && outgoingSession != this) {
            return outgoingSession.transformSending(msgText, tlvs);
        }
        if (msgText == null) {
            msgText = "";
        }
        if (tlvs == null) {
            tlvs = Collections.<TLV>emptyList();
        }
        final AbstractMessage m = this.sessionState.transformSending(this, msgText, tlvs);
        if (m == null) {
            return new String[0];
        }
        final String msgtext = SerializationUtils.toString(m);
        try {
            return this.fragmenter.fragment(msgtext);
        } catch (final IOException ex) {
            throw new OtrException("Failed to fragment message.", ex);
        }
    }

    @Override
    public void startSession() throws OtrException {
        if (this.getSessionStatus() == SessionStatus.ENCRYPTED) {
            logger.info("startSession was called, however an encrypted session is already established.");
            return;
        }
        logger.finest("Enquiring to start Authenticated Key Exchange, sending query message");
        final OtrPolicy policy = this.getSessionPolicy();
        final Set<Integer> allowedVersions = OtrPolicyUtil.allowedVersions(policy);
        if (allowedVersions.isEmpty()) {
            throw new IllegalStateException("Current OTR policy declines all supported versions of OTR. There is no way to start an OTR session that complies with the policy.");
        }
        injectMessage(new QueryMessage(allowedVersions));
    }

    public void endSession() throws OtrException {
        // TODO will this still work correctly? Can we determine OTRv3 session in case session is supported by slave session??!?!?!?!
        // TODO in any case, checking protocol version does not make sense here. In case of slave sessions, the master session may not have encrypted state (right?) outgoingSession is a good indicator though!
        if (this != outgoingSession) {
            outgoingSession.endSession();
            return;
        }
        this.sessionState.end(this);
    }

    /**
     * Refresh an existing ENCRYPTED session by ending and restarting it. Before
     * ending the session we record the current protocol version of the active
     * session. Afterwards, in case we received a valid version, we restart by
     * immediately sending a DH-Commit messages, as we already negotiated a
     * protocol version before and then we ended up with acquired version. In
     * case we weren't able to acquire a valid protocol version, we start by
     * sending a Query message.
     *
     * @throws OtrException Throws exception in case of failed session ending,
     * failed full session start, or failed creation or injection of DH-Commit
     * message.
     */
    public void refreshSession() throws OtrException {
        if (this.outgoingSession != this) {
            this.outgoingSession.refreshSession();
        }
        final int version = this.sessionState.getVersion();
        this.sessionState.end(this);
        if (version == 0) {
            startSession();
        } else {
            injectMessage(respondAuth(version, this.receiverTag));
        }
    }

    public PublicKey getRemotePublicKey() throws IncorrectStateException {
        if (this != outgoingSession) {
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

    @Override
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

    /**
     * Get the current session's protocol version. That is, in case no OTR
     * session is established (yet) it will return 0. This protocol version is
     * different from the protocol version in the current AKE conversation which
     * may be ongoing simultaneously. (See {@link #getAKEProtocolVersion() }.)
     *
     * @return Returns 0 for no session, or protocol version in case of
     * established OTR session.
     */
    @Override
    public int getProtocolVersion() {
        return this.sessionState.getVersion();
    }

    public List<Session> getInstances() {
        final List<Session> result = new ArrayList<>();
        result.add(this);
        result.addAll(slaveSessions.values());
        return result;
    }

    // FIXME can we be sure that outgoing session is only available in case an OTRv3 conversation was 
    public boolean setOutgoingInstance(@Nonnull final InstanceTag tag) {
        if (!masterSession) {
            // Only master session can set the outgoing session.
            return false;
        }
        final SessionID sessionId = this.sessionState.getSessionID();
        if (tag.equals(this.receiverTag)) {
            // FIXME not really changing outgoing session, do we really need to inform listeners?
            outgoingSession = this;
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionId);
            return true;
        }
        final Session newActiveSession = slaveSessions.get(tag);
        if (newActiveSession == null) {
            // FIXME strange that we assign outgoingSession to this then return false without signaling outgoingSessionChanged(...) event.
            outgoingSession = this;
            return false;
        } else {
            outgoingSession = newActiveSession;
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionId);
            return true;
        }
    }

    /**
     * Get session status for specified session.
     *
     * @param tag Instance tag identifying session. In case of
     * {@link InstanceTag#ZERO_TAG} queries session status for OTRv2 session.
     * @return Returns current session status.
     */
    @Nonnull
    public SessionStatus getSessionStatus(@Nonnull final InstanceTag tag) {
        if (tag.equals(this.receiverTag)) {
            return this.sessionState.getStatus();
        } else {
            // TODO does it really make sense to return this session's status if instance tag does not exist? I would expect it to be a plaintext session at best in that case.
            final Session slave = slaveSessions.get(tag);
            return slave == null ? this.sessionState.getStatus()
                    : slave.getSessionStatus();
        }
    }

    /**
     * Get remote public key for specified session.
     *
     * @param tag Instance tag identifying session. In case of
     * {@link InstanceTag#ZERO_TAG} queries session status for OTRv2 session.
     * @return Returns remote (long-term) public key.
     * @throws IncorrectStateException Thrown in case session's message state is
     * not ENCRYPTED.
     */
    @Nonnull
    public PublicKey getRemotePublicKey(@Nonnull final InstanceTag tag) throws IncorrectStateException {
        if (tag.equals(this.receiverTag)) {
            return this.sessionState.getRemotePublicKey();
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave == null ? this.sessionState.getRemotePublicKey()
                    : slave.getRemotePublicKey();
        }
    }

    /**
     * Get the currently set outgoing instance. This instance is used for
     * outgoing traffic.
     *
     * @return Returns session instance, possibly a slave session.
     */
    @Nonnull
    public Session getOutgoingInstance() {
        return outgoingSession;
    }

    /**
     * Respond to AKE query message.
     *
     * @param version OTR protocol version to use.
     * @param receiverTag The receiver tag to which to address the DH Commit
     * message. In case the receiver is not yet known (this is a valid use
     * case), specify {@link InstanceTag#ZERO_TAG}.
     * @return Returns DH commit message as response to AKE query.
     * @throws OtrException In case of invalid/unsupported OTR protocol version.
     */
    private DHCommitMessage respondAuth(final int version,
            @Nonnull final InstanceTag receiverTag) throws OtrException {
        if (!OTRv.ALL.contains(version)) {
            throw new OtrException("Only allowed versions are: 2, 3");
        }
        logger.finest("Responding to Query Message with D-H Commit message.");
        return this.authState.initiate(this, version, receiverTag);
    }

    /**
     * Initialize SMP negotiation.
     *
     * @param question The question, optional.
     * @param secret The secret to be verified using ZK-proof.
     * @throws OtrException In case of failure to init SMP or transform to
     * encoded message.
     */
    public void initSmp(@Nullable final String question, @Nonnull final String secret) throws OtrException {
        if (this != outgoingSession) {
            outgoingSession.initSmp(question, secret);
            return;
        }
        final SmpTlvHandler handler;
        try {
            handler = this.sessionState.getSmpTlvHandler();
        } catch (final IncorrectStateException ex) {
            // TODO consider if we want to throw an exception. In case this is not state ENCRYPTED, we know for sure SMP is not active.
            throw new OtrException(ex);
        }
        final List<TLV> tlvs = handler.initRespondSmp(question, secret, true);
        injectMessage(this.sessionState.transformSending(this, "", tlvs));
    }

    /**
     * Respond with SMP message for specified receiver tag.
     *
     * @param receiverTag The receiver instance tag.
     * @param question The question, optional.
     * @param secret The secret to be verified using ZK-proof.
     * @throws OtrException In case of failure.
     */
    public void respondSmp(@Nonnull final InstanceTag receiverTag, @Nullable final String question,
            @Nonnull final String secret) throws OtrException {
        if (receiverTag.equals(this.receiverTag)) {
            respondSmp(question, secret);
            return;
        }
        final Session slave = slaveSessions.get(receiverTag);
        if (slave != null) {
            slave.respondSmp(question, secret);
        } else {
            // FIXME is this really the appropriate response. If we are already in an ENCRYPTED message state, we should already have established OTRv2 or OTRv3. That means that we should never NOT find an instance tag. If we do find one, should we respond with OtrException?
            respondSmp(question, secret);
        }
    }

    /**
     * Respond to SMP request.
     *
     * @param question The question to be sent with SMP response, may be null.
     * @param secret The SMP secret that should be verified through ZK-proof.
     * @throws OtrException In case of failure to send, message state different
     * from ENCRYPTED, issues with SMP processing.
     */
    public void respondSmp(@Nullable final String question, @Nonnull final String secret) throws OtrException {
        if (this != outgoingSession) {
            outgoingSession.respondSmp(question, secret);
            return;
        }
        final List<TLV> tlvs;
        try {
            tlvs = this.sessionState.getSmpTlvHandler().initRespondSmp(question, secret, false);
        } catch (final IncorrectStateException ex) {
            throw new OtrException(ex);
        }
        injectMessage(this.sessionState.transformSending(this, "", tlvs));
    }

    /**
     * Abort running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    public void abortSmp() throws OtrException {
        if (this != outgoingSession) {
            outgoingSession.abortSmp();
            return;
        }
        final List<TLV> tlvs;
        try {
            tlvs = this.sessionState.getSmpTlvHandler().abortSmp();
        } catch (final IncorrectStateException ex) {
            throw new OtrException(ex);
        }
        injectMessage(this.sessionState.transformSending(this, "", tlvs));
    }

    /**
     * Check if SMP is in progress.
     *
     * @return Returns true if SMP is in progress, or false if not in progress.
     * Note that false will also be returned in case message state is not
     * ENCRYPTED.
     */
    public boolean isSmpInProgress() {
        if (this != outgoingSession) {
            return outgoingSession.isSmpInProgress();
        }
        try {
            return this.sessionState.getSmpTlvHandler().isSmpInProgress();
        } catch (final IncorrectStateException ex) {
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
        try {
            return this.sessionState.getExtraSymmetricKey();
        } catch (final IncorrectStateException ex) {
            throw new OtrException(ex);
        }
    }
}
