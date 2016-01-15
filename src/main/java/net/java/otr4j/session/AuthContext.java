/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Logger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureMessage;
import net.java.otr4j.io.messages.SignatureX;
import net.java.otr4j.session.Session.OTRv;

/**
 * @author George Politis
 */
public class AuthContext {

    public static final int NONE = 0;
    public static final int AWAITING_DHKEY = 1;
    public static final int AWAITING_REVEALSIG = 2;
    public static final int AWAITING_SIG = 3;
    public static final int V1_SETUP = 4;
    public static final byte C_START = (byte) 0x01;
    public static final byte M1_START = (byte) 0x02;
    public static final byte M2_START = (byte) 0x03;
    public static final byte M1p_START = (byte) 0x04;
    public static final byte M2p_START = (byte) 0x05;

    public AuthContext(final Session session) {
        SessionID sID = session.getSessionID();
        this.logger = Logger.getLogger(sID.getAccountID() + "-->" + sID.getUserID());
        this.setSession(session);
        this.reset();
    }

    // These parameters are initialized when generating D-H Commit Messages.
    // If the Session that this AuthContext belongs to is the 'master' session
    // then these parameters must be replicated to all slave session's auth
    // contexts.
    byte[] r;
    KeyPair localDHKeyPair;
    byte[] localDHPublicKeyBytes;
    byte[] localDHPublicKeyHash;
    byte[] localDHPublicKeyEncrypted;

    // TODO most likely session instance can be made final
    private Session session;

    private int authenticationState;

    private DHPublicKey remoteDHPublicKey;
    private byte[] remoteDHPublicKeyEncrypted;
    private byte[] remoteDHPublicKeyHash;

    private int localDHPrivateKeyID;

    // TODO consider storing this data in a separate container such that it is impossible to accidentally access an uninitialized field directly, i.e. access through accessor method is enforced. (We can still initialize everything to zero to avoid unnecessary memory overhead if not/hardly used.)
    private BigInteger s;
    private byte[] c;
    private byte[] m1;
    private byte[] m2;
    private byte[] cp;
    private byte[] m1p;
    private byte[] m2p;

    private KeyPair localLongTermKeyPair;
    private Boolean isSecure = false;

    private final Logger logger;

    class MessageFactory {

        QueryMessage getQueryMessage() {
            final Vector<Integer> versions = new Vector<Integer>();
            versions.add(OTRv.TWO);
            versions.add(OTRv.THREE);
            return new QueryMessage(versions);
        }

        DHCommitMessage getDHCommitMessage() throws OtrException {
            final DHCommitMessage message = new DHCommitMessage(getSession().getProtocolVersion(),
                    getLocalDHPublicKeyHash(), getLocalDHPublicKeyEncrypted());
            message.senderInstanceTag = session.getSenderInstanceTag().getValue();
            message.receiverInstanceTag = InstanceTag.ZERO_VALUE;
            return message;
        }

        DHKeyMessage getDHKeyMessage() throws OtrException {
            final DHKeyMessage dhKeyMessage =
                    new DHKeyMessage(getSession().getProtocolVersion(),
                            (DHPublicKey) getLocalDHKeyPair().getPublic());
            dhKeyMessage.senderInstanceTag = getSession().getSenderInstanceTag().getValue();
            dhKeyMessage.receiverInstanceTag = getSession().getReceiverInstanceTag().getValue();
            return dhKeyMessage;
        }

        RevealSignatureMessage getRevealSignatureMessage() throws OtrException {
            try {
                final SignatureM m = new SignatureM((DHPublicKey) getLocalDHKeyPair()
                        .getPublic(), getRemoteDHPublicKey(),
                        getLocalLongTermKeyPair().getPublic(),
                        getLocalDHKeyPairID());

                final byte[] mhash = OtrCryptoEngine.sha256Hmac(SerializationUtils
                        .toByteArray(m), getM1());
                final byte[] signature = OtrCryptoEngine.sign(mhash,
                        getLocalLongTermKeyPair().getPrivate());

                final SignatureX mysteriousX = new SignatureX(
                        getLocalLongTermKeyPair().getPublic(),
                        getLocalDHKeyPairID(), signature);
                final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(getC(), null,
                        SerializationUtils.toByteArray(mysteriousX));

                final byte[] tmp = SerializationUtils.writeData(xEncrypted);

                final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(tmp, getM2());
                final RevealSignatureMessage revealSignatureMessage =
                        new RevealSignatureMessage(getSession().getProtocolVersion(),
                                xEncrypted, xEncryptedHash, getR());
                revealSignatureMessage.senderInstanceTag =
                        getSession().getSenderInstanceTag().getValue();
                revealSignatureMessage.receiverInstanceTag =
                        getSession().getReceiverInstanceTag().getValue();
                return revealSignatureMessage;
            } catch (IOException e) {
                throw new OtrException(e);
            }
        }

        SignatureMessage getSignatureMessage() throws OtrException {
            final SignatureM m = new SignatureM((DHPublicKey) getLocalDHKeyPair()
                    .getPublic(), getRemoteDHPublicKey(),
                    getLocalLongTermKeyPair().getPublic(),
                    getLocalDHKeyPairID());

            final byte[] mhash;
            try {
                mhash = OtrCryptoEngine.sha256Hmac(SerializationUtils.toByteArray(m), getM1p());
            } catch (IOException e) {
                throw new OtrException(e);
            }

            final byte[] signature = OtrCryptoEngine.sign(mhash,
                    getLocalLongTermKeyPair().getPrivate());

            final SignatureX mysteriousX = new SignatureX(getLocalLongTermKeyPair()
                    .getPublic(), getLocalDHKeyPairID(), signature);

            try {
                final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(getCp(), null,
                        SerializationUtils.toByteArray(mysteriousX));
                final byte[] tmp = SerializationUtils.writeData(xEncrypted);
                final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(tmp, getM2p());
                final SignatureMessage signatureMessage =
                        new SignatureMessage(getSession().getProtocolVersion(), xEncrypted,
                                xEncryptedHash);
                signatureMessage.senderInstanceTag =
                        getSession().getSenderInstanceTag().getValue();
                signatureMessage.receiverInstanceTag =
                        getSession().getReceiverInstanceTag().getValue();
                return signatureMessage;
            } catch (IOException e) {
                throw new OtrException(e);
            }
        }
    }

    private final MessageFactory messageFactory = new MessageFactory();

    /**
     * Reset resets the state of the AuthContext.
     *
     * Reset is made final so that it cannot be overridden to make sure that
     * cleaning state does not accidentally fail.
     */
    public final void reset() {
        logger.finest("Resetting authentication state.");
        authenticationState = AuthContext.NONE;
        r = null;

        remoteDHPublicKey = null;
        remoteDHPublicKeyEncrypted = null;
        remoteDHPublicKeyHash = null;

        localDHKeyPair = null;
        localDHPrivateKeyID = 1;
        localDHPublicKeyBytes = null;
        localDHPublicKeyHash = null;
        localDHPublicKeyEncrypted = null;

        s = null;
        c = m1 = m2 = cp = m1p = m2p = null;

        localLongTermKeyPair = null;
        setIsSecure(false);
    }

    private void setIsSecure(Boolean isSecure) {
        // TODO dumb private setter is useless. Direct field access is available.
        this.isSecure = isSecure;
    }

    public boolean getIsSecure() {
        return isSecure;
    }

    void setAuthenticationState(final int authenticationState) {
        this.authenticationState = authenticationState;
    }

    private int getAuthenticationState() {
        return authenticationState;
    }

    private byte[] getR() {
        if (r == null) {
            logger.finest("Picking random key r.");
            r = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
            this.session.secureRandom().nextBytes(r);
        }
        return r;
    }

    private void setRemoteDHPublicKey(final DHPublicKey dhPublicKey) {
        // Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
        if (dhPublicKey.getY().compareTo(OtrCryptoEngine.MODULUS_MINUS_TWO) > 0) {
            throw new IllegalArgumentException(
                    "Illegal D-H Public Key value, Ignoring message.");
        } else if (dhPublicKey.getY().compareTo(OtrCryptoEngine.BIGINTEGER_TWO) < 0) {
            throw new IllegalArgumentException(
                    "Illegal D-H Public Key value, Ignoring message.");
        }
        logger.finest("Received D-H Public Key is a legal value.");

        this.remoteDHPublicKey = dhPublicKey;
    }

    public DHPublicKey getRemoteDHPublicKey() {
        return remoteDHPublicKey;
    }

    private void setRemoteDHPublicKeyEncrypted(final byte[] remoteDHPublicKeyEncrypted) {
        logger.finest("Storing encrypted remote public key.");
        this.remoteDHPublicKeyEncrypted = remoteDHPublicKeyEncrypted;
    }

    private byte[] getRemoteDHPublicKeyEncrypted() {
        return remoteDHPublicKeyEncrypted;
    }

    private void setRemoteDHPublicKeyHash(final byte[] remoteDHPublicKeyHash) {
        logger.finest("Storing encrypted remote public key hash.");
        this.remoteDHPublicKeyHash = remoteDHPublicKeyHash;
    }

    private byte[] getRemoteDHPublicKeyHash() {
        return remoteDHPublicKeyHash;
    }

    public KeyPair getLocalDHKeyPair() throws OtrException {
        if (localDHKeyPair == null) {
            localDHKeyPair = OtrCryptoEngine.generateDHKeyPair(this.session.secureRandom());
            logger.finest("Generated local D-H key pair.");
        }
        return localDHKeyPair;
    }

    private int getLocalDHKeyPairID() {
        return localDHPrivateKeyID;
    }

    private byte[] getLocalDHPublicKeyHash() throws OtrException {
        if (localDHPublicKeyHash == null) {
            localDHPublicKeyHash = OtrCryptoEngine.sha256Hash(getLocalDHPublicKeyBytes());
            logger.finest("Hashed local D-H public key.");
        }
        return localDHPublicKeyHash;
    }

    private byte[] getLocalDHPublicKeyEncrypted() throws OtrException {
        if (localDHPublicKeyEncrypted == null) {
            localDHPublicKeyEncrypted = OtrCryptoEngine.aesEncrypt(
                    getR(), null, getLocalDHPublicKeyBytes());
            logger.finest("Encrypted our D-H public key.");
        }
        return localDHPublicKeyEncrypted;
    }

    public BigInteger getS() throws OtrException {
        if (s == null) {
            s = OtrCryptoEngine.generateSecret(this
                    .getLocalDHKeyPair().getPrivate(), this
                    .getRemoteDHPublicKey());
            logger.finest("Generated shared secret.");
        }
        return s;
    }

    private byte[] getC() throws OtrException {
        if (c != null) {
            return c;
        }

        final byte[] h2 = h2(C_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        this.c = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        buff.get(this.c);
        logger.finest("Computed c.");
        return c;
    }

    private byte[] getM1() throws OtrException {
        if (m1 != null) {
            return m1;
        }

        final byte[] h2 = h2(M1_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        final byte[] m1 = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
        buff.get(m1);
        logger.finest("Computed m1.");
        this.m1 = m1;
        return m1;
    }

    byte[] getM2() throws OtrException {
        if (m2 != null) {
            return m2;
        }

        final byte[] h2 = h2(M2_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        final byte[] m2 = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
        buff.get(m2);
        logger.finest("Computed m2.");
        this.m2 = m2;
        return m2;
    }

    private byte[] getCp() throws OtrException {
        if (cp != null) {
            return cp;
        }

        final byte[] h2 = h2(C_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        final byte[] cp = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        buff.position(OtrCryptoEngine.AES_KEY_BYTE_LENGTH);
        buff.get(cp);
        logger.finest("Computed c'.");
        this.cp = cp;
        return cp;
    }

    private byte[] getM1p() throws OtrException {
        if (m1p != null) {
            return m1p;
        }

        final byte[] h2 = h2(M1p_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        final byte[] m1p = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
        buff.get(m1p);
        this.m1p = m1p;
        logger.finest("Computed m1'.");
        return m1p;
    }

    byte[] getM2p() throws OtrException {
        if (m2p != null) {
            return m2p;
        }

        final byte[] h2 = h2(M2p_START);
        final ByteBuffer buff = ByteBuffer.wrap(h2);
        final byte[] m2p = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
        buff.get(m2p);
        this.m2p = m2p;
        logger.finest("Computed m2'.");
        return m2p;
    }

    public KeyPair getLocalLongTermKeyPair() throws OtrException {
        if (localLongTermKeyPair == null) {
            localLongTermKeyPair = getSession().getLocalKeyPair();
        }
        return localLongTermKeyPair;
    }

    private byte[] h2(final byte b) throws OtrException {
        final byte[] secbytes;
        try {
            secbytes = SerializationUtils.writeMpi(getS());
        } catch (IOException e) {
            throw new OtrException(e);
        }

        final int len = secbytes.length + 1;
        final ByteBuffer buff = ByteBuffer.allocate(len);
        buff.put(b);
        buff.put(secbytes);
        final byte[] sdata = buff.array();
        return OtrCryptoEngine.sha256Hash(sdata);
    }

    private byte[] getLocalDHPublicKeyBytes() throws OtrException {
        if (localDHPublicKeyBytes == null) {
            try {
                this.localDHPublicKeyBytes = SerializationUtils
                        .writeMpi(((DHPublicKey) getLocalDHKeyPair()
                                .getPublic()).getY());
            } catch (IOException e) {
                throw new OtrException(e);
            }
        }
        return localDHPublicKeyBytes;
    }

    public void handleReceivingMessage(final AbstractMessage m) throws OtrException {

        switch (m.messageType) {
            case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
                handleDHCommitMessage((DHCommitMessage) m);
                break;
            case AbstractEncodedMessage.MESSAGE_DHKEY:
                handleDHKeyMessage((DHKeyMessage) m);
                break;
            case AbstractEncodedMessage.MESSAGE_REVEALSIG:
                handleRevealSignatureMessage((RevealSignatureMessage) m);
                break;
            case AbstractEncodedMessage.MESSAGE_SIGNATURE:
                handleSignatureMessage((SignatureMessage) m);
                break;
            default:
                throw new UnsupportedOperationException();
        }
    }

    private void handleSignatureMessage(final SignatureMessage m) throws OtrException {
        // TODO use of getSession() getter is redundant. Local variable might be needed to ensure all method calls are on the same instance of Session.
        final Session session = getSession();
        final SessionID sessionID = session.getSessionID();
        logger.finest(sessionID.getAccountID()
                + " received a signature message from " + sessionID.getUserID()
                + " through " + sessionID.getProtocolName() + ".");

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

        switch (this.getAuthenticationState()) {
            case AWAITING_SIG:
                // Verify MAC.
                if (!m.verify(this.getM2p())) {
                    logger.finest("Signature MACs are not equal, ignoring message.");
                    return;
                }

                // Decrypt X.
                final byte[] remoteXDecrypted = m.decrypt(this.getCp());
                final SignatureX remoteX;
                try {
                    remoteX = SerializationUtils.toMysteriousX(remoteXDecrypted);
                } catch (IOException e) {
                    throw new OtrException(e);
                }
                // Compute signature.
                final PublicKey remoteLongTermPublicKey = remoteX.longTermPublicKey;
                final SignatureM remoteM = new SignatureM(this.getRemoteDHPublicKey(),
                        (DHPublicKey) this.getLocalDHKeyPair().getPublic(),
                        remoteLongTermPublicKey, remoteX.dhKeyID);
                // Verify signature.
                final byte[] signature;
                try {
                    signature = OtrCryptoEngine.sha256Hmac(SerializationUtils
                            .toByteArray(remoteM), this.getM1p());
                } catch (IOException e) {
                    throw new OtrException(e);
                }
                if (!OtrCryptoEngine.verify(signature, remoteLongTermPublicKey,
                        remoteX.signature)) {
                    logger.finest("Signature verification failed.");
                    return;
                }

                this.setIsSecure(true);
                this.setRemoteLongTermPublicKey(remoteLongTermPublicKey);
                break;
            default:
                logger.finest("We were not expecting a signature, ignoring message.");
                return;
        }
        // TODO consider throwing IllegalStateException as we should never get here
    }

    private void handleRevealSignatureMessage(final RevealSignatureMessage m)
            throws OtrException {
        // TODO use of getSession() getter is redundant. Local variable might be needed to ensure all method calls are on the same instance of Session.
        final Session session = getSession();
        final SessionID sessionID = session.getSessionID();
        logger.finest(sessionID.getAccountID()
                + " received a reveal signature message from "
                + sessionID.getUserID() + " through "
                + sessionID.getProtocolName() + ".");
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

        switch (this.getAuthenticationState()) {
            case AWAITING_REVEALSIG:
                // Use the received value of r to decrypt the value of gx
                // received
                // in the D-H Commit Message, and verify the hash therein.
                // Decrypt
                // the encrypted signature, and verify the signature and the
                // MACs.
                // If everything checks out:

                // * Reply with a Signature Message.
                // * Transition authstate to AUTHSTATE_NONE.
                // * Transition msgstate to MSGSTATE_ENCRYPTED.
                // * TODO If there is a recent stored message, encrypt it and
                // send
                // it as a Data Message.

                // Uses r to decrypt the value of gx sent earlier
                final byte[] remoteDHPublicKeyDecrypted = OtrCryptoEngine.aesDecrypt(
                        m.revealedKey, null, this.getRemoteDHPublicKeyEncrypted());

                // Verifies that HASH(gx) matches the value sent earlier
                final byte[] remoteDHPublicKeyHash = OtrCryptoEngine
                        .sha256Hash(remoteDHPublicKeyDecrypted);
                if (!Arrays.equals(remoteDHPublicKeyHash, this
                        .getRemoteDHPublicKeyHash())) {
                    logger.finest("Hashes don't match, ignoring message.");
                    return;
                }

                // Verifies that Bob's gx is a legal value (2 <= gx <=
                // modulus-2)
                final BigInteger remoteDHPublicKeyMpi;
                try {
                    remoteDHPublicKeyMpi = SerializationUtils
                            .readMpi(remoteDHPublicKeyDecrypted);
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                this.setRemoteDHPublicKey(OtrCryptoEngine
                        .getDHPublicKey(remoteDHPublicKeyMpi));

                // Verify received Data.
                if (!m.verify(this.getM2())) {
                    logger.finest("Signature MACs are not equal, ignoring message.");
                    return;
                }

                // Decrypt X.
                final byte[] remoteXDecrypted = m.decrypt(this.getC());
                final SignatureX remoteX;
                try {
                    remoteX = SerializationUtils.toMysteriousX(remoteXDecrypted);
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                // Compute signature.
                final PublicKey remoteLongTermPublicKey = remoteX.longTermPublicKey;
                final SignatureM remoteM = new SignatureM(this.getRemoteDHPublicKey(),
                        (DHPublicKey) this.getLocalDHKeyPair().getPublic(),
                        remoteLongTermPublicKey, remoteX.dhKeyID);

                // Verify signature.
                final byte[] signature;
                try {
                    signature = OtrCryptoEngine.sha256Hmac(SerializationUtils
                            .toByteArray(remoteM), this.getM1());
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                if (!OtrCryptoEngine.verify(signature, remoteLongTermPublicKey,
                        remoteX.signature)) {
                    logger.finest("Signature verification failed.");
                    return;
                }

                logger.finest("Signature verification succeeded.");

                this.setAuthenticationState(AuthContext.NONE);
                this.setIsSecure(true);
                this.setRemoteLongTermPublicKey(remoteLongTermPublicKey);
                getSession().injectMessage(messageFactory.getSignatureMessage());
                break;
            default:
                logger.finest("Ignoring message.");
                break;
        }
    }

    private void handleDHKeyMessage(final DHKeyMessage m) throws OtrException {
        // TODO use of getSession() getter is redundant. Local variable might be needed to ensure all method calls are on the same instance of Session.
        final Session session = getSession();
        final SessionID sessionID = session.getSessionID();
        logger.finest(sessionID.getAccountID()
                + " received a D-H key message from " + sessionID.getUserID()
                + " through " + sessionID.getProtocolName() + ".");

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
        switch (this.getAuthenticationState()) {
            case NONE:
            case AWAITING_DHKEY:
                // Reply with a Reveal Signature Message and transition
                // authstate to
                // AUTHSTATE_AWAITING_SIG
                this.setRemoteDHPublicKey(m.dhPublicKey);
                this.setAuthenticationState(AuthContext.AWAITING_SIG);
                getSession().injectMessage(
                        messageFactory.getRevealSignatureMessage());
                logger.finest("Sent Reveal Signature.");
                break;
            case AWAITING_SIG:

                if (m.dhPublicKey.getY().equals(this.getRemoteDHPublicKey().getY())) {
                    // If this D-H Key message is the same the one you received
                    // earlier (when you entered AUTHSTATE_AWAITING_SIG):
                    // Retransmit
                    // your Reveal Signature Message.
                    getSession().injectMessage(
                            messageFactory.getRevealSignatureMessage());
                    logger.finest("Resent Reveal Signature.");
                } else {
                    // Otherwise: Ignore the message.
                    logger.finest("Ignoring message.");
                }
                break;
            default:
                // Ignore the message
                break;
        }
    }

    private void handleDHCommitMessage(final DHCommitMessage m) throws OtrException {
        final Session session = getSession();
        final SessionID sessionID = session.getSessionID();
        logger.finest(sessionID.getAccountID()
                + " received a D-H commit message from "
                + sessionID.getUserID() + " through "
                + sessionID.getProtocolName() + ".");

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
        switch (this.getAuthenticationState()) {
            case NONE:
                // Reply with a D-H Key Message, and transition authstate to
                // AUTHSTATE_AWAITING_REVEALSIG.
                this.reset();
                getSession().setProtocolVersion(m.protocolVersion);
                this.setRemoteDHPublicKeyEncrypted(m.dhPublicKeyEncrypted);
                this.setRemoteDHPublicKeyHash(m.dhPublicKeyHash);
                this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
                getSession().injectMessage(messageFactory.getDHKeyMessage());
                logger.finest("Sent D-H key.");
                break;

            case AWAITING_DHKEY:
                // This is the trickiest transition in the whole protocol. It
                // indicates that you have already sent a D-H Commit message to
                // your
                // correspondent, but that he either didn't receive it, or just
                // didn't receive it yet, and has sent you one as well. The
                // symmetry
                // will be broken by comparing the hashed gx you sent in your
                // D-H
                // Commit Message with the one you received, considered as
                // 32-byte
                // unsigned big-endian values.
                final BigInteger ourHash = new BigInteger(1, this
                        .getLocalDHPublicKeyHash());
                final BigInteger theirHash = new BigInteger(1, m.dhPublicKeyHash);

                if (theirHash.compareTo(ourHash) == -1) {
                    // Ignore the incoming D-H Commit message, but resend your
                    // D-H Commit message.
                    getSession().injectMessage(messageFactory.getDHCommitMessage());
                    logger.finest("Ignored the incoming D-H Commit message, but resent our D-H Commit message.");
                } else {
                    // *Forget* your old gx value that you sent (encrypted)
                    // earlier,
                    // and pretend you're in AUTHSTATE_NONE; i.e. reply with a
                    // D-H Key Message, and transition authstate to
                    // AUTHSTATE_AWAITING_REVEALSIG.
                    this.reset();
                    getSession().setProtocolVersion(m.protocolVersion);
                    this.setRemoteDHPublicKeyEncrypted(m.dhPublicKeyEncrypted);
                    this.setRemoteDHPublicKeyHash(m.dhPublicKeyHash);
                    this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
                    getSession().injectMessage(messageFactory.getDHKeyMessage());
                    logger.finest("Forgot our old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sent D-H key.");
                }
                break;

            case AWAITING_REVEALSIG:
                // Retransmit your D-H Key Message (the same one as you sent
                // when
                // you entered AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H
                // Commit message, and use this new one instead.
                this.setRemoteDHPublicKeyEncrypted(m.dhPublicKeyEncrypted);
                this.setRemoteDHPublicKeyHash(m.dhPublicKeyHash);
                getSession().injectMessage(messageFactory.getDHKeyMessage());
                logger.finest("Sent D-H key.");
                break;
            case AWAITING_SIG:
                // Reply with a new D-H Key message, and transition authstate to
                // AUTHSTATE_AWAITING_REVEALSIG
                this.reset();
                this.setRemoteDHPublicKeyEncrypted(m.dhPublicKeyEncrypted);
                this.setRemoteDHPublicKeyHash(m.dhPublicKeyHash);
                this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
                getSession().injectMessage(messageFactory.getDHKeyMessage());
                logger.finest("Sent D-H key.");
                break;
            case V1_SETUP:
                throw new UnsupportedOperationException();
        }
    }

    public void startAuth() throws OtrException {
        logger.finest("Starting Authenticated Key Exchange, sending query message");
        getSession().injectMessage(messageFactory.getQueryMessage());
    }

    public DHCommitMessage respondAuth(final Integer version) throws OtrException {
        if (version != OTRv.TWO && version != OTRv.THREE) {
            throw new OtrException(new Exception("Only allowed versions are: 2, 3"));
        }

        logger.finest("Responding to Query Message");
        this.reset();
        getSession().setProtocolVersion(version);
        this.setAuthenticationState(AuthContext.AWAITING_DHKEY);
        logger.finest("Generating D-H Commit.");
        return messageFactory.getDHCommitMessage();
    }

    private void setSession(final Session session) {
        // TODO dumb private setter is useless. Direct field access is available.
        this.session = session;
    }

    private Session getSession() {
        // TODO dumb private getter is useless. Direct field access is available.
        return session;
    }

    private PublicKey remoteLongTermPublicKey;

    public PublicKey getRemoteLongTermPublicKey() {
        return remoteLongTermPublicKey;
    }

    private void setRemoteLongTermPublicKey(final PublicKey pubKey) {
        // TODO dumb private setter is useless. Direct field access is available.
        this.remoteLongTermPublicKey = pubKey;
    }
}
