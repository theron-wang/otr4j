/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.AuthContext;
import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

public final class StateEncrypted extends AbstractState {

    @SuppressWarnings("NonConstantLogger")
    private final Logger logger;
    private final SessionID sessionId;
    private final int protocolVersion;
    private final SmpTlvHandler smpTlvHandler;

    /**
     * Shared secret s.
     */
    private final BigInteger s;

    /**
     * Long-term remote public key.
     */
    private final PublicKey remotePublicKey;

    /**
     * Current and next session keys.
     */
    private final SessionKeys[][] sessionKeys = new SessionKeys[][]{
        new SessionKeys[]{new SessionKeys(0, 0), new SessionKeys(0, 1)},
        new SessionKeys[]{new SessionKeys(1, 0), new SessionKeys(1, 1)}};

    /**
     * List of old MAC keys for this session. (Synchronized)
     */
    private final List<byte[]> oldMacKeys = Collections.synchronizedList(new ArrayList<byte[]>(0));

    StateEncrypted(@Nonnull final Context context, @Nonnull final SessionID sessionId) throws OtrException {
        // FIXME Identify session state in logger
        this.logger = Logger.getLogger(sessionId.getAccountID() + "-->" + sessionId.getUserID());
        this.sessionId = Objects.requireNonNull(sessionId);
        this.protocolVersion = context.getProtocolVersion();
        this.smpTlvHandler = new SmpTlvHandler(this, context);

        final AuthContext auth = context.getAuthContext();
        if (!auth.getIsSecure()) {
            // This should not happen. We should only transition states on fully
            // successful auth negotiation.
            throw new IllegalArgumentException("AuthContext is not fully secure");
        }

        this.s = auth.getS();
        this.remotePublicKey = auth.getRemoteLongTermPublicKey();

        // Initialize current session keys
        logger.finest("Setting most recent session keys from auth.");
        for (final SessionKeys current : this.sessionKeys[0]) {
            current.setLocalPair(auth.getLocalDHKeyPair(), 1);
            current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
            current.setS(auth.getS());
        }

        // Prepare for next session keys
        final KeyPair nextDH = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        for (final SessionKeys next : this.sessionKeys[1]) {
            next.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
            next.setLocalPair(nextDH, 2);
        }

        auth.reset(null);
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionId;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpTlvHandler() {
        return this.smpTlvHandler;
    }

    @Override
    @Nonnull
    public PublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Nonnull
    public BigInteger getS() {
        return this.s;
    }
    
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) throws OtrException {
        // Display the message to the user, but warn him that the message was
        // received unencrypted.
        OtrEngineHostUtil.unencryptedMessageReceived(context.getHost(),
                sessionId, plainTextMessage.cleanText);
        return plainTextMessage.cleanText;
    }
    
    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage data) throws OtrException {
        logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        final OtrEngineHost host = context.getHost();
        // Find matching session keys.
        final int senderKeyID = data.senderKeyID;
        final int receipientKeyID = data.recipientKeyID;
        final SessionKeys matchingKeys = this.getSessionKeysByID(receipientKeyID,
                senderKeyID);

        if (matchingKeys == null) {
            logger.finest("No matching keys found.");
            OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
            final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
            return null;
        }

        // Verify received MAC with a locally calculated MAC.
        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] serializedT;
        try {
            serializedT = SerializationUtils.toByteArray(data.getT());
        } catch (IOException e) {
            throw new OtrException(e);
        }

        final byte[] computedMAC = OtrCryptoEngine.sha1Hmac(serializedT,
                matchingKeys.getReceivingMACKey(),
                SerializationConstants.TYPE_LEN_MAC);
        if (!Arrays.equals(computedMAC, data.mac)) {
            logger.finest("MAC verification failed, ignoring message");
            OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
            final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
            return null;
        }

        logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.setIsUsedReceivingMACKey(true);

        matchingKeys.setReceivingCtr(data.ctr);

        final byte[] dmc = OtrCryptoEngine.aesDecrypt(matchingKeys
                .getReceivingAESKey(), matchingKeys.getReceivingCtr(),
                data.encryptedMessage);

        // Rotate keys if necessary.
        final SessionKeys mostRecent = this.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == receipientKeyID) {
            this.rotateLocalSessionKeys(context.secureRandom());
        }

        if (mostRecent.getRemoteKeyID() == senderKeyID) {
            this.rotateRemoteSessionKeys(data.nextDH);
        }

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = dmc.length;
        for (int i = 0; i < dmc.length; i++) {
            if (dmc[i] == 0x00) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String decryptedMsgContent = new String(dmc, 0, tlvIndex, SerializationUtils.UTF8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final LinkedList<TLV> tlvs = new LinkedList<TLV>();
        tlvIndex++;  // to ignore the null
        if (tlvIndex < dmc.length) {
            byte[] tlvsb = new byte[dmc.length - tlvIndex];
            System.arraycopy(dmc, tlvIndex, tlvsb, 0, tlvsb.length);

            final ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
            final OtrInputStream eois = new OtrInputStream(tin);
            try {
                while (tin.available() > 0) {
                    final int type = eois.readShort();
                    final byte[] tdata = eois.readTlvData();
                    tlvs.add(new TLV(type, tdata));
                }
            } catch (IOException e) {
                throw new OtrException(e);
            } finally {
                try {
                    eois.close();
                } catch (IOException e) {
                    throw new OtrException(e);
                }
            }
        }
        if (!tlvs.isEmpty()) {
            for (final TLV tlv : tlvs) {
                logger.log(Level.FINE, "Received TLV type {0}", tlv.getType());
                switch (tlv.getType()) {
                    case TLV.PADDING: // TLV0
                        // nothing to do here, just ignore the padding
                        break;
                    case TLV.DISCONNECTED: // TLV1
                        context.setState(new StateFinished(this.sessionId));
                        break;
                    case TLV.SMP1Q: //TLV7
                        this.smpTlvHandler.processTlvSMP1Q(tlv);
                        break;
                    case TLV.SMP1: // TLV2
                        this.smpTlvHandler.processTlvSMP1(tlv);
                        break;
                    case TLV.SMP2: // TLV3
                        this.smpTlvHandler.processTlvSMP2(tlv);
                        break;
                    case TLV.SMP3: // TLV4
                        this.smpTlvHandler.processTlvSMP3(tlv);
                        break;
                    case TLV.SMP4: // TLV5
                        this.smpTlvHandler.processTlvSMP4(tlv);
                        break;
                    case TLV.SMP_ABORT: //TLV6
                        this.smpTlvHandler.processTlvSMP_ABORT(tlv);
                        break;
                    default:
                        logger.log(Level.WARNING, "Unsupported TLV #{0} received!", tlv.getType());
                        break;
                }
            }
        }
        return decryptedMsgContent;
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        final OtrPolicy policy = context.getSessionPolicy();
        if (!policy.getErrorStartAKE()) {
            return;
        }
        // Re-negotiate if we got an error and we are encrypted
        logger.finest("Error message starts AKE.");
        final ArrayList<Integer> versions = new ArrayList<Integer>(4);
        if (policy.getAllowV1()) {
            versions.add(Session.OTRv.ONE);
        }
        if (policy.getAllowV2()) {
            versions.add(Session.OTRv.TWO);
        }
        if (policy.getAllowV3()) {
            versions.add(Session.OTRv.THREE);
        }
        logger.finest("Sending Query");
        context.injectMessage(new QueryMessage(versions));
        super.handleErrorMessage(context, errorMessage);
    }

    @Override
    @Nonnull
    public String[] transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        logger.log(Level.FINEST, "{0} sends an encrypted message to {1} through {2}.", new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});

        // Get encryption keys.
        final SessionKeys encryptionKeys = this.getEncryptionSessionKeys();
        final int senderKeyID = encryptionKeys.getLocalKeyID();
        final int receipientKeyID = encryptionKeys.getRemoteKeyID();

        // Increment CTR.
        encryptionKeys.incrementSendingCtr();
        final byte[] ctr = encryptionKeys.getSendingCtr();

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (msgText.length() > 0) {
            try {
                out.write(SerializationUtils.convertTextToBytes(msgText));
            } catch (IOException e) {
                throw new OtrException(e);
            }
        }

        // Append tlvs
        if (!tlvs.isEmpty()) {
            out.write((byte) 0x00);

            final OtrOutputStream eoos = new OtrOutputStream(out);
            try {
                for (TLV tlv : tlvs) {
                    eoos.writeShort(tlv.getType());
                    eoos.writeTlvData(tlv.getValue());
                }
            } catch (IOException ex) {
                throw new OtrException(ex);
            } finally {
                try {
                    eoos.close();
                } catch (IOException e) {
                    throw new OtrException(e);
                }
            }
        }

        final byte[] data = out.toByteArray();
        // Encrypt message.
        logger.log(Level.FINEST, "Encrypting message with keyids (localKeyID, remoteKeyID) = ({0}, {1})", new Object[]{senderKeyID, receipientKeyID});
        final byte[] encryptedMsg = OtrCryptoEngine.aesEncrypt(encryptionKeys
                .getSendingAESKey(), ctr, data);

        // Get most recent keys to get the next D-H public key.
        final SessionKeys mostRecentKeys = this.getMostRecentSessionKeys();
        final DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalPair()
                .getPublic();

        // Calculate T.
        final MysteriousT t
                = new MysteriousT(this.protocolVersion,
                        context.getSenderInstanceTag().getValue(),
                        context.getReceiverInstanceTag().getValue(),
                        0, senderKeyID, receipientKeyID, nextDH, ctr,
                        encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.getSendingMACKey();

        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] serializedT;
        try {
            serializedT = SerializationUtils.toByteArray(t);
        } catch (IOException e) {
            throw new OtrException(e);
        }

        final byte[] mac = OtrCryptoEngine.sha1Hmac(serializedT, sendingMACKey,
                SerializationConstants.TYPE_LEN_MAC);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.collectOldMacKeys();
        final DataMessage m = new DataMessage(t, mac, oldKeys);
        m.senderInstanceTag = context.getSenderInstanceTag().getValue();
        m.receiverInstanceTag = context.getReceiverInstanceTag().getValue();

        try {
            // FIXME Consider moving fragmenter to Session object, probably need to introduce "PlainMessage" type that does not add any kind of additional (meta)data.
            final String completeMessage = SerializationUtils.toString(m);
            return context.fragmenter().fragment(completeMessage);
        } catch (IOException e) {
            throw new OtrException(e);
        }
    }

    @Override
    public void secure(@Nonnull final Context context) throws OtrException {
        context.setState(new StateEncrypted(context, this.sessionId));
    }

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, null);
        final String[] msg = transformSending(context, "", Collections.singletonList(disconnectTlv));
        for (final String part : msg) {
            context.getHost().injectMessage(this.sessionId, part);
        }
        context.setState(new StatePlaintext(this.sessionId));
    }

    private void rotateRemoteSessionKeys(final DHPublicKey pubKey)
            throws OtrException {

        logger.finest("Rotating remote keys.");
        final SessionKeys sess1 = this.sessionKeys[SessionKeys.CURRENT][SessionKeys.PREVIOUS];
        if (sess1.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            this.oldMacKeys.add(sess1.getReceivingMACKey());
        }

        final SessionKeys sess2 = this.sessionKeys[SessionKeys.PREVIOUS][SessionKeys.PREVIOUS];
        if (sess2.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            this.oldMacKeys.add(sess2.getReceivingMACKey());
        }

        final SessionKeys sess3 = this.sessionKeys[SessionKeys.CURRENT][SessionKeys.CURRENT];
        sess1.setRemoteDHPublicKey(sess3.getRemoteKey(), sess3.getRemoteKeyID());

        final SessionKeys sess4 = this.sessionKeys[SessionKeys.PREVIOUS][SessionKeys.CURRENT];
        sess2.setRemoteDHPublicKey(sess4.getRemoteKey(), sess4.getRemoteKeyID());

        sess3.setRemoteDHPublicKey(pubKey, sess3.getRemoteKeyID() + 1);
        sess4.setRemoteDHPublicKey(pubKey, sess4.getRemoteKeyID() + 1);
    }

    private void rotateLocalSessionKeys(@Nonnull final SecureRandom secureRandom) throws OtrException {

        logger.finest("Rotating local keys.");
        final SessionKeys sess1 = this.sessionKeys[SessionKeys.PREVIOUS][SessionKeys.CURRENT];
        if (sess1.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            this.oldMacKeys.add(sess1.getReceivingMACKey());
        }

        final SessionKeys sess2 = this.sessionKeys[SessionKeys.PREVIOUS][SessionKeys.PREVIOUS];
        if (sess2.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            this.oldMacKeys.add(sess2.getReceivingMACKey());
        }

        final SessionKeys sess3 = this.sessionKeys[SessionKeys.CURRENT][SessionKeys.CURRENT];
        sess1.setLocalPair(sess3.getLocalPair(), sess3.getLocalKeyID());
        final SessionKeys sess4 = this.sessionKeys[SessionKeys.CURRENT][SessionKeys.PREVIOUS];
        sess2.setLocalPair(sess4.getLocalPair(), sess4.getLocalKeyID());

        final KeyPair newPair = OtrCryptoEngine.generateDHKeyPair(secureRandom);
        sess3.setLocalPair(newPair, sess3.getLocalKeyID() + 1);
        sess4.setLocalPair(newPair, sess4.getLocalKeyID() + 1);
    }

    private SessionKeys getEncryptionSessionKeys() {
        logger.finest("Getting encryption keys");
        return this.sessionKeys[SessionKeys.PREVIOUS][SessionKeys.CURRENT];
    }

    private SessionKeys getMostRecentSessionKeys() {
        logger.finest("Getting most recent keys.");
        return this.sessionKeys[SessionKeys.CURRENT][SessionKeys.CURRENT];
    }

    private SessionKeys getSessionKeysByID(final int localKeyID, final int remoteKeyID) {
        logger.log(Level.FINEST, "Searching for session keys with (localKeyID, remoteKeyID) = ({0},{1})",
                new Object[]{localKeyID, remoteKeyID});

        for (final SessionKeys[] sessionKey : this.sessionKeys) {
            for (final SessionKeys current : sessionKey) {
                if (current.getLocalKeyID() == localKeyID
                        && current.getRemoteKeyID() == remoteKeyID) {
                    logger.finest("Matching keys found.");
                    return current;
                }
            }
        }

        return null;
    }

    private byte[] collectOldMacKeys() {
        logger.finest("Collecting old MAC keys to be revealed.");
        synchronized (this.oldMacKeys) {
            int len = 0;
            for (final byte[] k : this.oldMacKeys) {
                len += k.length;
            }

            final ByteBuffer buff = ByteBuffer.allocate(len);
            for (final byte[] k : this.oldMacKeys) {
                buff.put(k);
            }

            this.oldMacKeys.clear();
            return buff.array();
        }
    }

}
