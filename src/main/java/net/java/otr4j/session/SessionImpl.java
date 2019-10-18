/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import com.google.errorprone.annotations.concurrent.GuardedBy;
import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineHosts;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrEngineListeners;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Fragment;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.io.QueryMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.IncorrectStateException;
import net.java.otr4j.session.state.State;
import net.java.otr4j.session.state.StateEncrypted;
import net.java.otr4j.session.state.StatePlaintext;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.OtrEngineHosts.messageFromAnotherInstanceReceived;
import static net.java.otr4j.api.OtrEngineListeners.duplicate;
import static net.java.otr4j.api.OtrEngineListeners.outgoingSessionChanged;
import static net.java.otr4j.api.OtrEngineListeners.sessionStatusChanged;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.Session.Version.THREE;
import static net.java.otr4j.api.Session.Version.TWO;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;
import static net.java.otr4j.messages.EncodedMessageParser.checkAuthRMessage;
import static net.java.otr4j.messages.EncodedMessageParser.checkDHKeyMessage;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static net.java.otr4j.session.state.State.FLAG_NONE;
import static net.java.otr4j.util.Objects.requireEquals;
import static net.java.otr4j.util.Objects.requireNotEquals;

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
 * <p>
 * SessionImpl is thread-safe. Thread-safety is achieved by serializing method calls of a session instance to the
 * corresponding master session. As the master session contains itself as master session, we can serialize both master
 * and slave sessions without concerns. Given that both synchronize to the master, we cannot use two slaves at the same
 * time. On the other hand, there are no complications with potential dead-locks, given that there is only one lock to
 * take.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO consider moving away from recursive use of Session, to delegating class with a number of instances of Session for each instance, with OTRv2 using zero-instance-tag. (Can delegating class be stateless? Would simplify managing thread-safety.)
@SuppressWarnings("PMD.TooManyFields")
final class SessionImpl implements Session, Context {

    private static final String DEFAULT_FALLBACK_MESSAGE = "Your contact is requesting to start an encrypted chat. Please install an app that supports OTR: https://github.com/otr4j/otr4j/wiki/Apps";

    /**
     * Session state contains the currently active message state of the session.
     * <p>
     * The message state, being plaintext, encrypted or finished, is the
     * instance that contains the logic concerning message handling for both
     * incoming and outgoing messages, and everything related to this message
     * state.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private State sessionState;

    /**
     * Slave sessions contain the mappings of instance tags to outgoing
     * sessions. In case of the master session, it is initialized with an empty
     * instance. In case of slaves the slaveSessions instance is initialized to
     * an (immutable) empty map.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private final Map<InstanceTag, SessionImpl> slaveSessions;

    @Nonnull
    private final SessionID sessionID;

    /**
     * The currently selected slave session that will be used as the session
     * for outgoing messages.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private SessionImpl outgoingSession;

    /**
     * Flag indicating whether this instance is a master session or a slave session.
     * <p>
     * This field will contain the master session instance for all slaves. It will self-reference in case of the master
     * session instance. Therefore, the master session need never be null.
     */
    @GuardedBy("itself")
    @Nonnull
    private final SessionImpl masterSession;

    /**
     * The Engine Host instance. This is a reference to the host logic that uses
     * OTR. The reference is used to call back into the program logic in order
     * to query for parameters that are determined by the program logic.
     */
    @Nonnull
    private final OtrEngineHost host;

    @SuppressWarnings({"NonConstantLogger", "PMD.LoggerIsNotStaticFinal"})
    private final Logger logger;

    /**
     * Offer status for whitespace-tagged message indicating OTR supported.
     */
    @GuardedBy("masterSession")
    private OfferStatus offerStatus;

    /**
     * The Client Profile.
     */
    private final ClientProfile profile;

    /**
     * The OTR-encodable, signed payload containing the client profile, ready to be sent.
     */
    // TODO refresh client profile payload after it is expired. (Maybe leave until after initial use, as expiration date is recommended for 2+ weeks.)
    // TODO consider keeping an internal class-level cache of signed payload per client profile, such that we do not keep constructing it again and again
    // TODO ability for user to specify amount of expiration time on a profile
    // TODO ability to identify when a new Client Profile is composed such that we need to refresh and republish the Client Profile payload.
    private final ClientProfilePayload profilePayload;

    /**
     * Receiver instance tag.
     * <p>
     * The receiver tag is only used in OTRv3. In case of OTRv2 the instance tag
     * will be zero-tag ({@link InstanceTag#ZERO_TAG}).
     */
    private final InstanceTag receiverTag;

    /**
     * OTR-encoded message-assembler.
     */
    @GuardedBy("masterSession")
    private final OtrAssembler assembler = new OtrAssembler();

    /**
     * Message fragmenter.
     */
    @GuardedBy("masterSession")
    private final OtrFragmenter fragmenter;

    /**
     * Secure random instance to be used for this Session. This single SecureRandom instance is there to be shared among
     * the classes in this package in order to support this specific Session instance. The SecureRandom instance should
     * not be shared between sessions.
     */
    private final SecureRandom secureRandom;

    /**
     * List of registered listeners.
     * <p>
     * Synchronized access is required. This is currently managed in methods
     * accessing the list.
     */
    @GuardedBy("masterSession")
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<>();

    /**
     * Listener for propagating events from slave sessions to the listeners of
     * the master session. The same instance is reused for all slave sessions.
     */
    @GuardedBy("masterSession")
    private final OtrEngineListener slaveSessionsListener = new OtrEngineListener() {

        // TODO temporarily suppress PMD warning due to false-positive in use of existing static import. (https://github.com/pmd/pmd/issues/1316)
        @SuppressWarnings("PMD.UnnecessaryFullyQualifiedName")
        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void sessionStatusChanged(final SessionID sessionID, final InstanceTag receiver) {
            OtrEngineListeners.sessionStatusChanged(duplicate(listeners), sessionID, receiver);
        }

        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void multipleInstancesDetected(final SessionID sessionID) {
            throw new IllegalStateException("Multiple instances should be detected in the master session. This event should never have happened.");
        }

        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void outgoingSessionChanged(final SessionID sessionID) {
            throw new IllegalStateException("Outgoing session changes should be performed in the master session only. This event should never have happened.");
        }
    };

    /**
     * Message queue for messages queued until private messaging session is established.
     * <p>
     * The message queue is shared between master and slave sessions.
     */
    @GuardedBy("masterSession")
    private final ArrayList<String> messageQueue;

    /**
     * Constructor for setting up a master session.
     * <p>
     * Package-private constructor for creating new sessions. To create a sessions without using the OTR session
     * manager, we offer a static method that (indirectly) provides access to the session implementation. See
     * {@link OtrSessionManager#createSession(SessionID, OtrEngineHost)}.
     * <p>
     * This constructor constructs a master session instance.
     *
     * @param sessionID The session ID
     * @param host      The OTR engine host listener.
     */
    SessionImpl(final SessionID sessionID, final OtrEngineHost host) {
        this(null, sessionID, host, ZERO_TAG, new SecureRandom(), new ArrayList<String>());
    }

    /**
     * Constructor for setting up either a master or a slave session. (Only masters construct a slave session.)
     *
     * @param masterSession The master session instance. The provided instance is set as the master session. In case of
     *                      the master session, null can be provided to indicate that this session instance is the
     *                      master session. Providing null, sets the master session instance to this session.
     * @param sessionID     The session ID.
     * @param host          OTR engine host instance.
     * @param receiverTag   The receiver instance tag. The receiver instance tag is allowed to be ZERO.
     * @param secureRandom  The secure random instance.
     */
    private SessionImpl(@Nullable final SessionImpl masterSession, final SessionID sessionID, final OtrEngineHost host,
            final InstanceTag receiverTag, final SecureRandom secureRandom, final ArrayList<String> messageQueue) {
        this.masterSession = masterSession == null ? this : masterSession;
        assert this.masterSession.masterSession == this.masterSession : "BUG: expected master session to be its own master session. This is likely an illegal state.";
        this.secureRandom = requireNonNull(secureRandom);
        this.sessionID = requireNonNull(sessionID);
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.host = requireNonNull(host);
        this.receiverTag = requireNonNull(receiverTag);
        this.messageQueue = requireNonNull(messageQueue);
        this.offerStatus = OfferStatus.IDLE;
        // Master session uses the map to manage slave sessions. Slave sessions do not use the map.
        if (this.masterSession == this) {
            this.slaveSessions = new HashMap<>(0);
        } else {
            this.slaveSessions = emptyMap();
        }
        outgoingSession = this;
        this.sessionState = new StatePlaintext(StateInitial.instance());
        // Initialize the Client Profile and payload.
        ClientProfilePayload payload;
        ClientProfile profile;
        try {
            // Try to restore previous Client Profile payload from host application.
            payload = ClientProfilePayload.readFrom(new OtrInputStream(this.host.restoreClientProfilePayload()));
            profile = payload.validate();
        } catch (final OtrCryptoException | ProtocolException | ValidationException e) {
            // We need to construct a new Client Profile payload based on the Client Profile received from the host
            // application.
            profile = this.host.getClientProfile(sessionID);
            requireNotEquals(ZERO_TAG, profile.getInstanceTag(), "Only actual instance tags are allowed. The 'zero' tag is not valid.");
            final Calendar expirationDate = Calendar.getInstance();
            expirationDate.add(Calendar.DAY_OF_YEAR, 14);
            payload = signClientProfile(profile, expirationDate.getTimeInMillis() / 1000,
                    this.host.getLocalKeyPair(sessionID), this.host.getLongTermKeyPair(sessionID));
            this.host.publishClientProfilePayload(new OtrOutputStream().write(payload).toByteArray());
        }
        this.profile = profile;
        this.profilePayload = payload;
        // Initialize message fragmentation support.
        this.fragmenter = new OtrFragmenter(this.secureRandom, host, this.sessionID);
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

    @Nonnull
    @Override
    public DSAKeyPair getLocalKeyPair() {
        return this.host.getLocalKeyPair(this.sessionID);
    }

    @Nonnull
    @Override
    public ClientProfilePayload getClientProfilePayload() {
        return this.profilePayload;
    }

    @GuardedBy("masterSession")
    @Override
    public void setAuthState(final AuthState state) {
        if (this.sessionState.getAuthState().getTimestamp() > state.getTimestamp()) {
            throw new IllegalArgumentException("BUG: we always expect to replace a state instance with a more recent state.");
        }
        this.sessionState.setAuthState(state);
    }

    @GuardedBy("masterSession")
    @Override
    public void transition(final State fromState, final State toState) {
        requireEquals(this.sessionState, fromState,
                "BUG: provided \"from\" state is not the current state. Expected " + this.sessionState + ", but got " + fromState);
        if (toState instanceof StateEncrypted) {
            sendQueuedMessages((StateEncrypted) toState);
        }
        logger.log(FINE, "Transitioning to message state: " + toState);
        this.sessionState = requireNonNull(toState);
        if (fromState.getStatus() != ENCRYPTED && toState.getStatus() == ENCRYPTED
                && this.masterSession.getOutgoingSession().getSessionStatus() == PLAINTEXT) {
            // This behavior is adopted to preserve behavior between otr4j before refactoring and after. Originally,
            // the master session would contain some fields that would indicate session status even though a slave
            // session was created. Now we ensure that once we have secured the session, we also switch to that
            // session such that subsequently sent messages are already encrypted, even if the client does not
            // explicitly switch.
            logger.finest("Switching to the just-secured session, as the previous state was an insecure state.");
            this.masterSession.setOutgoingSession(getReceiverInstanceTag());
        }
        fromState.destroy();
        sessionStatusChanged(duplicate(listeners), this.sessionID, this.receiverTag);
    }

    @GuardedBy("masterSession")
    private void sendQueuedMessages(final StateEncrypted toState) {
        while (!this.messageQueue.isEmpty()) {
            final String message = this.messageQueue.remove(0);
            try {
                final AbstractEncodedMessage encrypted = toState.transformSending(this, message,
                        Collections.<TLV>emptyList(), (byte) 0);
                injectMessage(encrypted);
            } catch (final OtrException e) {
                logger.log(WARNING, "Failed to send queued message due to network failure.", e);
            }
        }
    }

    @Override
    @Nonnull
    public SessionStatus getSessionStatus() {
        synchronized (this.masterSession) {
            synchronized (this.outgoingSession.masterSession) {
                return this.outgoingSession.sessionState.getStatus();
            }
        }
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionID;
    }

    @Override
    @Nonnull
    public OtrEngineHost getHost() {
        return host;
    }

    @Override
    @Nonnull
    public OfferStatus getOfferStatus() {
        synchronized (this.masterSession) {
            return this.offerStatus;
        }
    }

    @Override
    public void setOfferStatusSent() {
        synchronized (this.masterSession) {
            this.offerStatus = OfferStatus.SENT;
        }
    }

    @Override
    @Nullable
    public String transformReceiving(final String msgText) throws OtrException {
        synchronized (this.masterSession) {
            logger.log(FINEST, "Entering {0} session.", masterSession == this ? "master" : "slave");

            if (msgText.length() == 0) {
                return msgText;
            }

            final OtrPolicy policy = getSessionPolicy();
            if (!policy.viable()) {
                logger.info("Policy does not allow any version of OTR. OTR messages will not be processed at all.");
                return msgText;
            }

            final Message m;
            try {
                m = parseMessage(msgText);
            } catch (final ProtocolException e) {
                throw new OtrException("Invalid message received.", e);
            }

            if (m instanceof PlainTextMessage) {
                if (offerStatus == OfferStatus.SENT) {
                    offerStatus = OfferStatus.REJECTED;
                }
            } else {
                offerStatus = OfferStatus.ACCEPTED;
            }

            // FIXME evaluate inter-play between master and slave sessions. How much of certainty do we have if we reset the state from within one of the AKE states, that we actually reset sufficiently? In most cases, context.setState will manipulate the slave session, not the master session, so the influence limited.
            if (masterSession == this && m instanceof Fragment && (((Fragment) m).getVersion() == THREE
                    || ((Fragment) m).getVersion() == FOUR)) {
                final Fragment fragment = (Fragment) m;

                if (ZERO_TAG.equals(fragment.getSenderTag())) {
                    logger.log(INFO, "Message fragment contains 0 sender tag. Ignoring message. (Message ID: {0}, index: {1}, total: {2})",
                            new Object[] {fragment.getIdentifier(), fragment.getIndex(), fragment.getTotal()});
                    return null;
                }

                if (!ZERO_TAG.equals(fragment.getReceiverTag())
                        && fragment.getReceiverTag().getValue() != this.profile.getInstanceTag().getValue()) {
                    // The message is not intended for us. Discarding...
                    logger.finest("Received a message fragment with receiver instance tag that is different from ours. Ignore this message.");
                    messageFromAnotherInstanceReceived(this.host, this.sessionID);
                    return null;
                }

                if (!this.slaveSessions.containsKey(fragment.getSenderTag())) {
                    final SessionImpl newSlaveSession = new SessionImpl(this, sessionID, this.host,
                            fragment.getSenderTag(), this.secureRandom, this.messageQueue);
                    newSlaveSession.addOtrEngineListener(this.slaveSessionsListener);
                    this.slaveSessions.put(fragment.getSenderTag(), newSlaveSession);
                }
                final SessionImpl slave = this.slaveSessions.get(fragment.getSenderTag());
                return slave.handleFragment(fragment);
            } else if (masterSession == this && m instanceof EncodedMessage && (((EncodedMessage) m).version == THREE
                    || ((EncodedMessage) m).version == FOUR)) {
                final EncodedMessage message = (EncodedMessage) m;

                if (ZERO_TAG.equals(message.senderTag)) {
                    // An encoded message without a sender instance tag is always bad.
                    logger.warning("Encoded message is missing sender instance tag. Ignoring message.");
                    return null;
                }

                if (!ZERO_TAG.equals(message.receiverTag) && !message.receiverTag.equals(this.profile.getInstanceTag())) {
                    // The message is not intended for us. Discarding...
                    logger.finest("Received an encoded message with receiver instance tag that is different from ours. Ignore this message.");
                    messageFromAnotherInstanceReceived(this.host, sessionID);
                    return null;
                }

                if (!this.slaveSessions.containsKey(message.senderTag)) {
                    final SessionImpl newSlaveSession = new SessionImpl(this, sessionID, this.host,
                            message.senderTag, this.secureRandom, this.messageQueue);
                    newSlaveSession.addOtrEngineListener(this.slaveSessionsListener);
                    this.slaveSessions.put(message.senderTag, newSlaveSession);
                }

                final SessionImpl slave = this.slaveSessions.get(message.senderTag);
                logger.log(FINEST, "Delegating to slave session for instance tag {0}",
                        message.senderTag.getValue());
                return slave.handleEncodedMessage(message);
            }

            logger.log(FINE, "Received message with type {0}", m.getClass());
            if (m instanceof Fragment) {
                return handleFragment((Fragment) m);
            } else if (m instanceof EncodedMessage) {
                return handleEncodedMessage((EncodedMessage) m);
            } else if (m instanceof ErrorMessage) {
                handleErrorMessage((ErrorMessage) m);
                return null;
            } else if (m instanceof PlainTextMessage) {
                return handlePlainTextMessage((PlainTextMessage) m);
            } else if (m instanceof QueryMessage) {
                handleQueryMessage((QueryMessage) m);
                return null;
            } else {
                // At this point, the message m has a known type, but support was not implemented at this point in the code.
                // This should be considered a programming error. We should handle any known message type gracefully.
                // Unknown messages are caught earlier.
                throw new UnsupportedOperationException("This message type is not supported. Support is expected to be implemented for all known message types.");
            }
        }
    }

    /**
     * Handle message that is an OTR fragment.
     *
     * @param fragment fragment message.
     * @return Returns assembled and processed result of message fragment, in case fragment is final fragment. Or return
     * null in case fragment is not the last fragment and processing is delayed until remaining fragments are received.
     */
    @GuardedBy("masterSession")
    @Nullable
    private String handleFragment(final Fragment fragment) throws OtrException {
        assert this.masterSession != this || fragment.getVersion() == TWO
                : "BUG: Expect to only handle OTRv2 message fragments on master session. All other fragments should be handled on dedicated slave session.";
        final String reassembledText;
        try {
            reassembledText = assembler.accumulate(fragment);
            if (reassembledText == null) {
                logger.log(FINEST, "Fragment received, but message is still incomplete.");
                return null;
            }
        } catch (final ProtocolException e) {
            logger.log(FINE, "Rejected message fragment from sender instance "
                    + fragment.getSenderTag().getValue(), e);
            return null;
        }
        final EncodedMessage message;
        try {
            final Message m = parseMessage(reassembledText);
            if (!(m instanceof EncodedMessage)) {
                logger.fine("Expected fragments to combine into an encoded message, but was something else. "
                        + m.getClass().getName());
                return null;
            }
            message = (EncodedMessage) m;
        } catch (final ProtocolException e) {
            logger.log(WARNING, "Reassembled message violates the OTR protocol for encoded messages.", e);
            return null;
        }
        // There is no good reason why the reassembled message should have any other protocol version, sender
        // instance tag or receiver instance tag than the fragments themselves. For now, be safe and drop any
        // inconsistencies to ensure that the inconsistencies cannot be exploited.
        if (message.version != fragment.getVersion() || !message.senderTag.equals(fragment.getSenderTag())
                || !message.receiverTag.equals(fragment.getReceiverTag())) {
            logger.log(INFO, "Inconsistent OTR-encoded message: message contains different protocol version, sender tag or receiver tag than last received fragment. Message is ignored.");
            return null;
        }
        return handleEncodedMessage(message);
    }

    /**
     * Handle any kind of encoded message. (Either Data message or any type of AKE message.)
     *
     * @param message The encoded message.
     * @return Returns result of handling message, typically decrypting encoded messages or null if no presentable result.
     * @throws OtrException In case of failure to process.
     */
    @GuardedBy("masterSession")
    @Nullable
    private String handleEncodedMessage(final EncodedMessage message) throws OtrException {
        assert this.masterSession != this || message.version == TWO : "BUG: We should not process encoded message in master session for protocol version 3 or higher.";
        assert !ZERO_TAG.equals(message.senderTag) : "BUG: No encoded message without sender instance tag should reach this point.";
        if (message.version == THREE && checkDHKeyMessage(message)) {
            // Copy state to slave session, as this is the earliest moment that we know the instance tag of the other party.
            synchronized (this.masterSession.masterSession) {
                final AuthState slaveAuthState = this.sessionState.getAuthState();
                final AuthState masterAuthState = this.masterSession.sessionState.getAuthState();
                if (slaveAuthState.getTimestamp() < masterAuthState.getTimestamp()) {
                    this.sessionState.setAuthState(masterAuthState);
                }
            }
        } else if (checkAuthRMessage(message)) {
            assert this != this.masterSession : "We expected to be working inside a slave session instead of a master session.";
            // Copy state to slave session, as this is the earliest moment that we know the instance tag of the other party.
            // Note: this will *not* screw up the confidentiality guarantee, but only because we prevent messages from
            // being sent in StateAwaitingAuthR and StateAwaitingAuthI.
            synchronized (this.masterSession.masterSession) {
                this.sessionState = this.masterSession.sessionState;
            }
        }
        return this.sessionState.handleEncodedMessage(this, message);
    }

    @GuardedBy("masterSession")
    private void handleQueryMessage(final QueryMessage queryMessage) throws OtrException {
        assert this.masterSession == this : "BUG: handleQueryMessage should only ever be called from the master session, as no instance tags are known.";
        logger.log(FINEST, "{0} received a query message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});

        final OtrPolicy policy = getSessionPolicy();
        if (queryMessage.getVersions().contains(FOUR) && policy.isAllowV4()) {
            logger.finest("Query message with V4 support found. Sending Identity Message.");
            respondAuth(FOUR, ZERO_TAG);
        } else if (queryMessage.getVersions().contains(THREE) && policy.isAllowV3()) {
            logger.finest("Query message with V3 support found. Sending D-H Commit Message.");
            respondAuth(THREE, ZERO_TAG);
        } else if (queryMessage.getVersions().contains(TWO) && policy.isAllowV2()) {
            logger.finest("Query message with V2 support found. Sending D-H Commit Message.");
            respondAuth(TWO, ZERO_TAG);
        } else {
            logger.info("Query message received, but none of the versions are acceptable. They are either excluded by policy or through lack of support.");
        }
    }

    @GuardedBy("masterSession")
    private void handleErrorMessage(final ErrorMessage errorMessage)
            throws OtrException {
        assert this.masterSession == this : "BUG: handleErrorMessage should only ever be called from the master session, as no instance tags are known.";
        logger.log(FINEST, "{0} received an error message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});
        this.sessionState.handleErrorMessage(this, errorMessage);
    }

    @Override
    public void injectMessage(final Message m) throws OtrException {
        synchronized (this.masterSession) {
            final String serialized = writeMessage(m);
            final String[] fragments;
            if (m instanceof QueryMessage) {
                assert this.masterSession == this : "Expected query messages to only be sent from Master session!";
                assert !(m instanceof PlainTextMessage)
                        : "PlainText messages (with possible whitespace tag) should not end up here. We should not append the fallback message to a whitespace-tagged plaintext message.";
                final int spaceForFallbackMessage = host.getMaxFragmentSize(this.sessionID) - 1 - serialized.length();
                fragments = new String[] {serialized + ' ' + getFallbackMessage(this.sessionID, spaceForFallbackMessage)};
            } else if (m instanceof AbstractEncodedMessage) {
                final AbstractEncodedMessage encoded = (AbstractEncodedMessage) m;
                fragments = this.fragmenter.fragment(encoded.protocolVersion, encoded.senderTag.getValue(),
                        encoded.receiverTag.getValue(), serialized);
            } else {
                fragments = new String[] {serialized};
            }
            for (final String fragment : fragments) {
                this.host.injectMessage(this.sessionID, fragment);
            }
        }
    }

    @Nonnull
    private String getFallbackMessage(final SessionID sessionID, final int spaceLeft) {
        if (spaceLeft <= 0) {
            return "";
        }
        String fallback = OtrEngineHosts.getFallbackMessage(this.host, sessionID);
        if (fallback == null || fallback.isEmpty()) {
            fallback = DEFAULT_FALLBACK_MESSAGE;
        }
        if (fallback.length() > spaceLeft) {
            fallback = fallback.substring(0, spaceLeft);
        }
        return fallback;
    }

    @GuardedBy("masterSession")
    @Nonnull
    private String handlePlainTextMessage(final PlainTextMessage plainTextMessage) {
        assert this.masterSession == this : "BUG: handlePlainTextMessage should only ever be called from the master session, as no instance tags are known.";
        logger.log(FINEST, "{0} received a plaintext message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});
        final String messagetext = this.sessionState.handlePlainTextMessage(this, plainTextMessage);
        if (plainTextMessage.getVersions().isEmpty()) {
            logger.finest("Received plaintext message without the whitespace tag.");
        } else {
            logger.finest("Received plaintext message with the whitespace tag.");
            handleWhitespaceTag(plainTextMessage);
        }
        return messagetext;
    }

    @GuardedBy("masterSession")
    private void handleWhitespaceTag(final PlainTextMessage plainTextMessage) {
        final OtrPolicy policy = getSessionPolicy();
        if (!policy.isWhitespaceStartAKE()) {
            // no policy w.r.t. starting AKE on whitespace tag
            return;
        }
        logger.finest("WHITESPACE_START_AKE is set, processing whitespace-tagged message.");
        if (plainTextMessage.getVersions().contains(FOUR) && policy.isAllowV4()) {
            logger.finest("V4 tag found. Sending Identity Message.");
            try {
                respondAuth(FOUR, ZERO_TAG);
            } catch (final OtrException e) {
                logger.log(WARNING, "An exception occurred while constructing and sending Identity message. (OTRv4)", e);
            }
        } else if (plainTextMessage.getVersions().contains(THREE) && policy.isAllowV3()) {
            logger.finest("V3 tag found. Sending D-H Commit Message.");
            try {
                respondAuth(THREE, ZERO_TAG);
            } catch (final OtrException e) {
                logger.log(WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv3)", e);
            }
        } else if (plainTextMessage.getVersions().contains(TWO) && policy.isAllowV2()) {
            logger.finest("V2 tag found. Sending D-H Commit Message.");
            try {
                respondAuth(TWO, ZERO_TAG);
            } catch (final OtrException e) {
                logger.log(WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv2)", e);
            }
        } else {
            logger.info("Message with whitespace tags received, but none of the tags are useful. They are either excluded by policy or by lack of support.");
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
    @Override
    @Nonnull
    public String[] transformSending(final String msgText) throws OtrException {
        synchronized (this.masterSession) {
            return this.transformSending(msgText, Collections.<TLV>emptyList());
        }
    }

    /**
     * Transform message to be sent to content that is sendable over the IM
     * network.
     *
     * @param msgText the (normal) message content
     * @param tlvs    TLV items (must not be null, may be an empty list)
     * @return Returns the (array of) messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
    // TODO report message queued to host application instead of error. (Maybe make text of OtrEngineHost#requireEncryptedMessage conditional on whether or not queueing is enabled.)
    @Override
    @Nonnull
    public String[] transformSending(final String msgText, final Iterable<TLV> tlvs)
            throws OtrException {
        synchronized (this.masterSession) {
            if (masterSession == this && outgoingSession != this) {
                return outgoingSession.transformSending(msgText, tlvs);
            }
            final Message m = this.sessionState.transformSending(this, msgText, tlvs, FLAG_NONE);
            if (m == null) {
                return new String[0];
            }
            final String serialized = writeMessage(m);
            if (m instanceof AbstractEncodedMessage) {
                final AbstractEncodedMessage encoded = (AbstractEncodedMessage) m;
                return this.fragmenter.fragment(encoded.protocolVersion, encoded.senderTag.getValue(),
                        encoded.receiverTag.getValue(), serialized);
            }
            return new String[] {serialized};
        }
    }

    /**
     * Start a new OTR session by sending an OTR query message.
     * <p>
     * Consider using {@link OtrPolicy#viable()} to verify whether any version of the OTR protocol is allowed, such that
     * we can actually establish a private conversation.
     *
     * @throws OtrException Throws an error in case we failed to inject the
     *                      Query message into the host's transport channel.
     */
    @Override
    public void startSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this.getSessionStatus() == ENCRYPTED) {
                logger.info("startSession was called, however an encrypted session is already established.");
                return;
            }
            logger.finest("Enquiring to start Authenticated Key Exchange, sending query message");
            final OtrPolicy policy = this.getSessionPolicy();
            final Set<Integer> allowedVersions = allowedVersions(policy);
            if (allowedVersions.isEmpty()) {
                throw new OtrException("Current OTR policy declines all supported versions of OTR. There is no way to start an OTR session that complies with the policy.");
            }
            final QueryMessage queryMessage = new QueryMessage(allowedVersions);
            injectMessage(queryMessage);
        }
    }

    /**
     * End message state.
     *
     * @throws OtrException Throw OTR exception in case of failure during
     *                      ending.
     */
    @Override
    public void endSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                outgoingSession.endSession();
                return;
            }
            this.sessionState.end(this);
        }
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
     *                      failed full session start, or failed creation or injection of DH-Commit
     *                      message.
     */
    @Override
    public void refreshSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this.outgoingSession != this) {
                this.outgoingSession.refreshSession();
                return;
            }
            final int version = this.sessionState.getVersion();
            this.sessionState.end(this);
            if (version == 0) {
                startSession();
            } else {
                respondAuth(version, this.receiverTag);
            }
        }
    }

    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                return outgoingSession.getRemotePublicKey();
            }
            return this.sessionState.getRemotePublicKey();
        }
    }

    @Override
    public void addOtrEngineListener(final OtrEngineListener l) {
        synchronized (this.masterSession) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    @Override
    public void removeOtrEngineListener(final OtrEngineListener l) {
        synchronized (this.masterSession) {
            listeners.remove(l);
        }
    }

    @Override
    @Nonnull
    public OtrPolicy getSessionPolicy() {
        synchronized (this.masterSession) {
            return this.host.getSessionPolicy(this.sessionID);
        }
    }

    @Override
    @Nonnull
    public InstanceTag getSenderInstanceTag() {
        return this.profile.getInstanceTag();
    }

    @Override
    @Nonnull
    public InstanceTag getReceiverInstanceTag() {
        return receiverTag;
    }

    /**
     * Get the current session's protocol version. That is, in case no OTR
     * session is established (yet) it will return 0. This protocol version is
     * different from the protocol version in the current AKE conversation which
     * may be ongoing simultaneously.
     *
     * @return Returns 0 for no session, or protocol version in case of
     * established OTR session.
     */
    @Override
    public int getProtocolVersion() {
        synchronized (this.masterSession) {
            return this.sessionState.getVersion();
        }
    }

    /**
     * Get list of OTR session instances, i.e. sessions with different instance
     * tags. There is always at least 1 session, the master session or only
     * session in case of OTRv2.
     *
     * @return Returns list of session instances.
     */
    @Override
    @Nonnull
    public List<SessionImpl> getInstances() {
        synchronized (this.masterSession) {
            assert this == this.masterSession : "BUG: expected this method to be called from master session only.";
            final List<SessionImpl> result = new ArrayList<>();
            result.add(this);
            result.addAll(slaveSessions.values());
            return result;
        }
    }

    /**
     * Set the outgoing session to the session corresponding to the specified
     * Receiver instance tag. Setting the outgoing session is only allowed for
     * master sessions.
     */
    @Override
    public void setOutgoingSession(final InstanceTag tag) {
        synchronized (this.masterSession) {
            if (masterSession != this) {
                // Only master session can set the outgoing session.
                throw new UnsupportedOperationException("Only master session is allowed to set/change the outgoing session instance.");
            }
            if (tag.equals(this.receiverTag)) {
                outgoingSession = this;
                outgoingSessionChanged(duplicate(listeners), this.sessionID);
                return;
            }
            final SessionImpl newActiveSession = slaveSessions.get(tag);
            if (newActiveSession == null) {
                throw new IllegalArgumentException("No slave session exists with provided instance tag.");
            }
            outgoingSession = newActiveSession;
            outgoingSessionChanged(duplicate(listeners), this.sessionID);
        }
    }

    /**
     * Get session status for specified session.
     *
     * @param tag Instance tag identifying session. In case of
     *            {@link InstanceTag#ZERO_TAG} queries session status for OTRv2 session.
     * @return Returns current session status.
     */
    @Override
    @Nonnull
    public SessionStatus getSessionStatus(final InstanceTag tag) {
        synchronized (this.masterSession) {
            if (tag.equals(this.receiverTag)) {
                return this.sessionState.getStatus();
            }
            final SessionImpl slave = slaveSessions.get(tag);
            if (slave == null) {
                throw new IllegalArgumentException("Unknown instance tag specified: " + tag.getValue());
            }
            return slave.getSessionStatus();
        }
    }

    /**
     * Get remote public key for specified session.
     *
     * @param tag Instance tag identifying session. In case of
     *            {@link InstanceTag#ZERO_TAG} queries session status for OTRv2 session.
     * @return Returns remote (long-term) public key.
     * @throws IncorrectStateException Thrown in case session's message state is
     *                                 not ENCRYPTED.
     */
    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey(final InstanceTag tag) throws IncorrectStateException {
        synchronized (this.masterSession) {
            if (tag.equals(this.receiverTag)) {
                return this.sessionState.getRemotePublicKey();
            }
            final SessionImpl slave = slaveSessions.get(tag);
            if (slave == null) {
                throw new IllegalArgumentException("Unknown tag specified: " + tag.getValue());
            }
            return slave.getRemotePublicKey();
        }
    }

    /**
     * Get the currently set outgoing instance. This instance is used for
     * outgoing traffic.
     *
     * @return Returns session instance, possibly a slave session.
     */
    @Override
    @Nonnull
    public SessionImpl getOutgoingSession() {
        synchronized (this.masterSession) {
            return this.outgoingSession;
        }
    }

    /**
     * Respond to AKE query message.
     *
     * @param version     OTR protocol version to use.
     * @param receiverTag The receiver tag to which to address the DH Commit
     *                    message. In case the receiver is not yet known (this is a valid use
     *                    case), specify {@link InstanceTag#ZERO_TAG}.
     * @throws OtrException In case of invalid/unsupported OTR protocol version.
     */
    @GuardedBy("masterSession")
    private void respondAuth(final int version, final InstanceTag receiverTag) throws OtrException {
        if (!Version.SUPPORTED.contains(version)) {
            throw new OtrException("Unsupported OTR version encountered.");
        }
        // Ensure we initiate authentication state in master session, as we copy the master session's authentication
        // state upon receiving a DHKey message. This is caused by the fact that we may get multiple D-H Key responses
        // to a D-H Commit message without receiver instance tag. (This is due to the subtle workings of the
        // implementation.)
        logger.finest("Responding to Query Message, acknowledging version " + version);
        synchronized (this.masterSession.masterSession) {
            this.masterSession.sessionState.initiateAKE(this.masterSession, version, receiverTag);
        }
    }

    /**
     * Initialize SMP negotiation.
     *
     * @param question The question, optional.
     * @param answer   The answer to be verified using ZK-proof.
     * @throws OtrException In case of failure to init SMP or transform to encoded message.
     */
    @Override
    public void initSmp(@Nullable final String question, final String answer) throws OtrException {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                outgoingSession.initSmp(question, answer);
                return;
            }
            final State session = this.sessionState;
            if (!(session instanceof StateEncrypted)) {
                logger.log(INFO, "Not initiating SMP negotiation as we are currently not in an Encrypted messaging state.");
                return;
            }
            final StateEncrypted encrypted = (StateEncrypted) session;
            // First try, we may find that we get an SMP Abort response. A running SMP negotiation was aborted.
            final TLV tlv = encrypted.getSmpHandler().initiate(question == null ? "" : question, answer.getBytes(UTF_8));
            injectMessage(encrypted.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE));
            if (!encrypted.getSmpHandler().smpAbortedTLV(tlv)) {
                return;
            }
            // Second try, in case first try aborted an open negotiation. Initiations should be possible at any moment, even
            // if this aborts a running SMP negotiation.
            final TLV tlv2 = encrypted.getSmpHandler().initiate(question == null ? "" : question, answer.getBytes(UTF_8));
            injectMessage(encrypted.transformSending(this, "", singletonList(tlv2), FLAG_IGNORE_UNREADABLE));
        }
    }

    /**
     * Respond to SMP request.
     *
     * @param question The question to be sent with SMP response, may be null.
     * @param secret   The SMP secret that should be verified through ZK-proof.
     * @throws OtrException In case of failure to send, message state different
     *                      from ENCRYPTED, issues with SMP processing.
     */
    @Override
    public void respondSmp(@Nullable final String question, final String secret) throws OtrException {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                outgoingSession.respondSmp(question, secret);
                return;
            }
            sendResponseSmp(question, secret);
        }
    }

    /**
     * Respond with SMP message for specified receiver tag.
     *
     * @param receiverTag The receiver instance tag.
     * @param question    The question, optional.
     * @param secret      The secret to be verified using ZK-proof.
     * @throws OtrException In case of failure.
     */
    @Override
    public void respondSmp(final InstanceTag receiverTag, @Nullable final String question, final String secret)
            throws OtrException {
        synchronized (this.masterSession) {
            final SessionImpl session = receiverTag.equals(this.receiverTag) ? this : this.slaveSessions.get(receiverTag);
            if (session == null) {
                throw new IllegalArgumentException("Unknown receiver instance tag: " + receiverTag.getValue());
            }
            session.sendResponseSmp(question, secret);
        }
    }

    /**
     * Send SMP response.
     *
     * @param question (Optional) question
     * @param answer   answer of which we verify common knowledge
     * @throws OtrException In case of failure to send, message state different from ENCRYPTED, issues with SMP
     *                      processing.
     */
    @GuardedBy("masterSession")
    private void sendResponseSmp(@Nullable final String question, final String answer) throws OtrException {
        final State session = this.sessionState;
        final TLV tlv = session.getSmpHandler().respond(question == null ? "" : question, answer.getBytes(UTF_8));
        final Message m = session.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE);
        if (m != null) {
            injectMessage(m);
        }
    }

    /**
     * Abort running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    @Override
    public void abortSmp() throws OtrException {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                outgoingSession.abortSmp();
                return;
            }
            final State session = this.sessionState;
            final TLV tlv = session.getSmpHandler().abort();
            final Message m = session.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE);
            if (m != null) {
                injectMessage(m);
            }
        }
    }

    /**
     * Check if SMP is in progress.
     *
     * @return Returns true if SMP is in progress, or false if not in progress.
     * Note that false will also be returned in case message state is not ENCRYPTED.
     */
    @Override
    public boolean isSmpInProgress() {
        synchronized (this.masterSession) {
            if (this != outgoingSession) {
                return outgoingSession.isSmpInProgress();
            }
            try {
                return this.sessionState.getSmpHandler().getStatus() == INPROGRESS;
            } catch (final IncorrectStateException e) {
                return false;
            }
        }
    }

    /**
     * Acquire the extra symmetric key that can be derived from the session's
     * shared secret.
     * <p>
     * This extra key can also be derived by your chat counterpart. This key
     * never needs to be communicated. TLV 8, that is described in otr v3 spec,
     * is used to inform your counterpart that he needs to start using the key.
     * He can derive the actual key for himself, so TLV 8 should NEVER contain
     * this symmetric key data.
     *
     * @return Returns the extra symmetric key.
     * @throws OtrException In case the message state is not ENCRYPTED, there
     *                      exists no extra symmetric key to return.
     */
    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws OtrException {
        synchronized (this.masterSession) {
            return this.sessionState.getExtraSymmetricKey();
        }
    }

    /**
     * Get the moment of last activity relevant to this session.
     *
     * @return timestamp of last activity according to monotonic time ({@link System#nanoTime()})
     * @throws IncorrectStateException In case the session's current state does not recognize a significant notion of
     *                                 "last activity".
     */
    long getLastActivityTimestamp() throws IncorrectStateException {
        synchronized (this.masterSession) {
            return this.sessionState.getLastActivityTimestamp();
        }
    }

    /**
     * Expire the session.
     *
     * @throws OtrException Thrown in case of failure to fully expire the session.
     */
    void expireSession() throws OtrException {
        synchronized (this.masterSession) {
            final State state = this.sessionState;
            try {
                state.expire(this);
            } finally {
                state.destroy();
                sessionStatusChanged(duplicate(this.listeners), this.sessionID, this.receiverTag);
            }
        }
    }

    /**
     * Get the timestamp of the last message sent.
     * <p>
     * Returns a monotonic timestamp of the moment when the most recent message was sent. The message sent is
     * specifically a DataMessage, i.e. a message sent when a private messaging session is established.
     *
     * @return Returns the monotonic timestamp ({@link System#nanoTime()} of most recently sent message.
     * @throws IncorrectStateException In case session is not in private messaging state.
     */
    long getLastMessageSentTimestamp() throws IncorrectStateException {
        synchronized (this.masterSession) {
            return this.sessionState.getLastMessageSentTimestamp();
        }
    }

    /**
     * Send heartbeat message.
     *
     * @throws OtrException In case of failure to inject the heartbeat message into the communication channel.
     */
    void sendHeartbeat() throws OtrException {
        synchronized (this.masterSession) {
            final State state = this.sessionState;
            if (!(state instanceof StateEncrypted)) {
                return;
            }
            final AbstractEncodedMessage heartbeat = ((StateEncrypted) state).transformSending(this, "",
                    Collections.<TLV>emptyList(), FLAG_IGNORE_UNREADABLE);
            injectMessage(heartbeat);
        }
    }

    // TODO evaluate what to do with situation where multiple instances establish private messaging session concurrently. One will be first, it will receive the queued messages. These might not go to the client instance that we want to.
    @Override
    public void queueMessage(final String message) {
        synchronized (this.masterSession) {
            this.messageQueue.add(message);
        }
    }
}
