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
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.SmpTlvHandler;
import net.java.otr4j.session.state.State;
import net.java.otr4j.session.state.StatePlaintext;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO Define interface 'Session' that defines methods for general use, i.e. no intersecting methods with Context.
public class Session implements Context {

    public interface OTRv {
        // FIXME consider eliminating OTRv1 completely
        int ONE = 1;
        int TWO = 2;
        int THREE = 3;

        final Set<Integer> ALL = Collections.unmodifiableSet(
                new HashSet<Integer>(Arrays.asList(ONE, TWO, THREE)));
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
     * Slave sessions contain the mappings of instance tags to outgoing sessions.
     * In case of the master session, it is initialized with an empty instance.
     * In case of slaves the slaveSessions instance is initialized to 'null'.
     */
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
    private final boolean isMasterSession;

    private final OtrEngineHost host;

    // TODO consider instantiating AuthContext immediately at construction of the class
    private AuthContext authContext;
    
    private final Logger logger;

    /**
     * Offer status for whitespace-tagged message indicating OTR supported.
     */
    private OfferStatus offerStatus;
    private final InstanceTag senderTag;
    private InstanceTag receiverTag;
    private int protocolVersion;
    private final OtrAssembler assembler;
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
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<OtrEngineListener>();

    public Session(@Nonnull final SessionID sessionID, @Nonnull final OtrEngineHost listener) {
        this.secureRandom = new SecureRandom();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.sessionState = new StatePlaintext(sessionID);
        this.host = Objects.requireNonNull(listener);

        // client application calls OtrSessionManager.getSessionStatus()
        // -> create new session if it does not exist, end up here
        // -> setSessionStatus() fires statusChangedEvent
        // -> client application calls OtrSessionManager.getSessionStatus()
        this.offerStatus = OfferStatus.idle;

        this.senderTag = InstanceTag.random(this.secureRandom);
        this.receiverTag = InstanceTag.ZERO_TAG;

        // Start with initial capacity of 0. Will start to use more memory once
        // the map is in actual use.
        slaveSessions = Collections.synchronizedMap(new HashMap<InstanceTag, Session>(0));
        outgoingSession = this;
        isMasterSession = true;

        assembler = new OtrAssembler(this.senderTag);
        fragmenter = new OtrFragmenter(this, listener);
    }

    // A private constructor for instantiating 'slave' sessions.
    private Session(@Nonnull final SessionID sessionID,
            @Nonnull final OtrEngineHost listener,
            @Nonnull final InstanceTag senderTag,
            @Nonnull final InstanceTag receiverTag,
            @Nonnull final SecureRandom secureRandom,
            @Nullable final AuthContext authContext) {
        this.secureRandom = Objects.requireNonNull(secureRandom);
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.sessionState = new StatePlaintext(sessionID);
        this.host = Objects.requireNonNull(listener);

        this.offerStatus = OfferStatus.idle;

        this.senderTag = senderTag;
        this.receiverTag = receiverTag;

        // Slave sessions do not use this map. Initialize to null.
        slaveSessions = null;
        outgoingSession = this;
        isMasterSession = false;
        protocolVersion = OTRv.THREE;

        assembler = new OtrAssembler(this.senderTag);
        fragmenter = new OtrFragmenter(this, listener);
        
        if (authContext != null) {
            // In case an AuthContext is provided, duplicate AuthContext for
            // this session instance.
            this.authContext = new AuthContext(this, authContext);
        }
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
    public void setState(@Nonnull final State state) {
        this.sessionState = Objects.requireNonNull(state);
        OtrEngineListenerUtil.sessionStatusChanged(
                OtrEngineListenerUtil.duplicate(listeners), state.getSessionID());
    }

    public SessionStatus getSessionStatus() {
        return this.sessionState.getStatus();
    }

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
    public void setOfferStatus(@Nonnull final OfferStatus status) {
        this.offerStatus = Objects.requireNonNull(status);
    }
    
    @Override
    @Nonnull
    public AuthContext getAuthContext() {
        if (authContext == null) {
            authContext = new AuthContext(this);
        }
        return authContext;
    }

    @Nullable
    public String transformReceiving(@Nonnull String msgText) throws OtrException {

        final OtrPolicy policy = getSessionPolicy();
        if (!policy.getAllowV1() && !policy.getAllowV2() && !policy.getAllowV3()) {
            logger.finest("Policy does not allow neither V1 nor V2 & V3, ignoring message.");
            return msgText;
        }

        try {
            msgText = assembler.accumulate(msgText);
        } catch (final UnknownInstanceException e) {
            // The fragment is not intended for us
            logger.finest(e.getMessage());
            OtrEngineHostUtil.messageFromAnotherInstanceReceived(this.host, this.sessionState.getSessionID());
            return null;
        } catch (ProtocolException e) {
            logger.log(Level.WARNING, "An invalid message fragment was discarded.", e);
            return null;
        }

        if (msgText == null) {
            return null; // Not a complete message (yet).
        }

        final AbstractMessage m;
        try {
            m = SerializationUtils.toMessage(msgText);
        } catch (final IOException e) {
            throw new OtrException(e);
        }
        if (m == null) {
            return msgText; // Probably null or empty.
        }

        if (m.messageType != AbstractMessage.MESSAGE_PLAINTEXT) {
            offerStatus = OfferStatus.accepted;
        } else if (offerStatus == OfferStatus.sent) {
            offerStatus = OfferStatus.rejected;
        }

        if (m instanceof AbstractEncodedMessage && isMasterSession) {

            final AbstractEncodedMessage encodedM = (AbstractEncodedMessage) m;

            if (encodedM.protocolVersion == OTRv.THREE) {

                if (encodedM.receiverInstanceTag != this.getSenderInstanceTag().getValue()) {
                    if (!(encodedM.messageType == AbstractEncodedMessage.MESSAGE_DH_COMMIT
                    && encodedM.receiverInstanceTag == 0)) {

                        // The message is not intended for us. Discarding...
                        logger.finest("Received an encoded message with receiver instance tag" +
                                " that is different from ours, ignore this message");
                        OtrEngineHostUtil.messageFromAnotherInstanceReceived(this.host, this.sessionState.getSessionID());
                        return null;
                    }
                }

                if (encodedM.senderInstanceTag != this.getReceiverInstanceTag().getValue()
                        && this.getReceiverInstanceTag().getValue() != 0) {

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
                                    = new Session(this.sessionState.getSessionID(),
                                            this.host,
                                            getSenderInstanceTag(),
                                            newReceiverTag,
                                            this.secureRandom,
                                            encodedM.messageType == AbstractEncodedMessage.MESSAGE_DHKEY
                                                    ? this.getAuthContext() : null);
                            
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
                this.getAuthContext().handleReceivingMessage(m);
                return null;
            case AbstractEncodedMessage.MESSAGE_REVEALSIG:
            case AbstractEncodedMessage.MESSAGE_SIGNATURE:
                final AuthContext auth = this.getAuthContext();
                try {
                    auth.handleReceivingMessage(m);
                    if (auth.getIsSecure()) {
                        this.sessionState.secure(this);
                        logger.finest("Gone Secure.");
                    }
                    return null;
                } finally {
                    // This ensures that independent of processing result, we
                    // always reset the AuthContext after receiving these
                    // messages. (This is according to otr spec.)
                    auth.reset(null);
                }
            default:
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
            final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.THREE);
            if (isMasterSession) {
                synchronized (slaveSessions) {
                    for (final Session session : slaveSessions.values()) {
                        session.getAuthContext().reset(this.getAuthContext());
                    }
                }
            }
            injectMessage(dhCommit);
        }
        else if (queryMessage.versions.contains(OTRv.TWO) && policy.getAllowV2()) {
            logger.finest("Query message with V2 support found.");
            final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.TWO);
            logger.finest("Sending D-H Commit Message");
            injectMessage(dhCommit);
        } else if (queryMessage.versions.contains(OTRv.ONE) && policy.getAllowV1()) {
            // FIXME Get rid of OTRv1 support completely
            logger.finest("Query message with V1 support found - ignoring.");
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
        String msg;
        try {
            msg = SerializationUtils.toString(m);
        } catch (IOException e) {
            throw new OtrException(e);
        }
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
            } catch (IOException e) {
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
                final DHCommitMessage dhCommit = getAuthContext().respondAuth(Session.OTRv.THREE);
                if (isMasterSession) {
                    synchronized (slaveSessions) {
                        for (final Session session : slaveSessions.values()) {
                            session.getAuthContext().reset(this.getAuthContext());
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
                final DHCommitMessage dhCommit = getAuthContext().respondAuth(Session.OTRv.TWO);
                logger.finest("Sending D-H Commit Message");
                injectMessage(dhCommit);
            } catch (final OtrException e) {
                logger.log(Level.WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv2)", e);
            }
        } else if (plainTextMessage.versions.contains(Session.OTRv.ONE)
                && policy.getAllowV1()) {
            // FIXME Get rid of OTRv1 support completely
            throw new UnsupportedOperationException();
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
        if (isMasterSession && outgoingSession != this && getProtocolVersion() == OTRv.THREE) {
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
            return;
        }
        final OtrPolicy policy = getSessionPolicy();
        if (!policy.getAllowV2() && !policy.getAllowV3()) {
            throw new UnsupportedOperationException();
        }
        this.getAuthContext().startAuth();
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

    public KeyPair getLocalKeyPair() throws OtrException {
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

    public void setReceiverInstanceTag(@Nonnull final InstanceTag receiverTag) {
        // ReceiverInstanceTag of a slave session is not supposed to change
        if (!isMasterSession) {
            return;
        }
        this.receiverTag = receiverTag;
    }

    public void setProtocolVersion(final int protocolVersion) {
        // Protocol version of a slave session is not supposed to change
        if (!isMasterSession) {
            return;
        }
        this.protocolVersion = protocolVersion;
    }

    @Override
    public int getProtocolVersion() {
        return isMasterSession ? this.protocolVersion : 3;
    }

    public List<Session> getInstances() {
        final List<Session> result = new ArrayList<Session>();
        result.add(this);
        result.addAll(slaveSessions.values());
        return result;
    }

    public boolean setOutgoingInstance(@Nonnull final InstanceTag tag) {
        if (!isMasterSession) {
            // Only master session can set the outgoing session.
            return false;
        }
        final SessionID sessionId = this.sessionState.getSessionID();
        if (tag.equals(getReceiverInstanceTag())) {
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
        if (tag.equals(getReceiverInstanceTag())) {
            return this.sessionState.getStatus();
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave == null ? this.sessionState.getStatus()
                    : slave.getSessionStatus();
        }
    }

    @Nonnull
    public PublicKey getRemotePublicKey(@Nonnull final InstanceTag tag) throws State.IncorrectStateException {
        if (tag.equals(getReceiverInstanceTag())) {
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
        if (receiverTag.equals(getReceiverInstanceTag())) {
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
}
