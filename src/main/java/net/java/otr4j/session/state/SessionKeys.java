/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.SharedSecret;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
final class SessionKeys {

    static final int PREVIOUS = 0;
    static final int CURRENT = 1;
    static final byte HIGH_SEND_BYTE = (byte) 0x01;
    static final byte HIGH_RECEIVE_BYTE = (byte) 0x02;
    static final byte LOW_SEND_BYTE = (byte) 0x02;
    static final byte LOW_RECEIVE_BYTE = (byte) 0x01;

    private static final Logger LOGGER = Logger.getLogger(SessionKeys.class.getName());

    private final String keyDescription;
    
    private final SharedSecret s;

    private int localKeyID;
    private int remoteKeyID;
    private DHPublicKey remoteKey;
    private KeyPair localPair;

    private byte[] sendingAESKey;
    private byte[] receivingAESKey;
    private byte[] sendingMACKey;
    private byte[] receivingMACKey;
    private boolean isUsedReceivingMACKey;
    private boolean isHigh;

    SessionKeys(@Nonnull final SharedSecret s, final int localKeyIndex,
            final int remoteKeyIndex) {
        this.s = Objects.requireNonNull(s);
        final StringBuilder desc = new StringBuilder();
        if (localKeyIndex == 0) {
            desc.append("(Previous local, ");
        } else {
            desc.append("(Most recent local, ");
        }
        if (remoteKeyIndex == 0) {
            desc.append("Previous remote)");
        } else {
            desc.append("Most recent remote)");
        }
        this.keyDescription = desc.toString();
    }

    void setLocalPair(final KeyPair keyPair, final int localPairKeyID) {
        this.localPair = keyPair;
        this.localKeyID = localPairKeyID;
        LOGGER.log(Level.FINEST, "{0} current local key ID: {1}",
                new Object[]{keyDescription, this.localKeyID});
        this.reset();
    }

    void setRemoteDHPublicKey(final DHPublicKey pubKey, final int remoteKeyID) {
        this.remoteKey = pubKey;
        this.remoteKeyID = remoteKeyID;
        LOGGER.log(Level.FINEST, "{0} current remote key ID: {1}",
                new Object[]{keyDescription, this.remoteKeyID});
        this.reset();
    }

    private final byte[] sendingCtr = new byte[16];
    private final byte[] receivingCtr = new byte[16];

    void incrementSendingCtr() {
        LOGGER.log(Level.FINEST, "Incrementing counter for (localkeyID, remoteKeyID) = ({0},{1})",
                new Object[]{localKeyID, remoteKeyID});
        for (int i = 7; i >= 0; i--) {
            if (++sendingCtr[i] != 0) {
                break;
            }
        }
    }

    byte[] getSendingCtr() {
        return sendingCtr;
    }

    byte[] getReceivingCtr() {
        return receivingCtr;
    }

    void setReceivingCtr(@Nonnull final byte[] ctr) {
        System.arraycopy(ctr, 0, receivingCtr, 0, ctr.length);
    }

    private void reset() {
        LOGGER.log(Level.FINEST, "Resetting {0} session keys.", keyDescription);
        Arrays.fill(this.sendingCtr, (byte) 0x00);
        Arrays.fill(this.receivingCtr, (byte) 0x00);
        this.sendingAESKey = null;
        this.receivingAESKey = null;
        this.sendingMACKey = null;
        this.receivingMACKey = null;
        this.setIsUsedReceivingMACKey(false);
        if (localPair != null && remoteKey != null) {
            this.isHigh = ((DHPublicKey) localPair.getPublic()).getY()
                    .abs().compareTo(remoteKey.getY().abs()) == 1;
        }
    }

    byte[] getSendingAESKey() throws OtrException {
        if (sendingAESKey != null) {
            return sendingAESKey;
        }

        final byte sendbyte;
        if (this.isHigh) {
            sendbyte = HIGH_SEND_BYTE;
        } else {
            sendbyte = LOW_SEND_BYTE;
        }

        final byte[] h1 = this.s.h1(sendbyte);

        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        final ByteBuffer buff = ByteBuffer.wrap(h1);
        buff.get(key);
        LOGGER.finest("Calculated sending AES key.");
        this.sendingAESKey = key;
        return sendingAESKey;
    }

    byte[] getReceivingAESKey() throws OtrException {
        if (receivingAESKey != null) {
            return receivingAESKey;
        }

        final byte receivebyte;
        if (this.isHigh) {
            receivebyte = HIGH_RECEIVE_BYTE;
        } else {
            receivebyte = LOW_RECEIVE_BYTE;
        }

        final byte[] h1 = this.s.h1(receivebyte);

        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        final ByteBuffer buff = ByteBuffer.wrap(h1);
        buff.get(key);
        LOGGER.finest("Calculated receiving AES key.");
        this.receivingAESKey = key;

        return receivingAESKey;
    }

    byte[] getSendingMACKey() throws OtrException {
        if (sendingMACKey != null) {
            return sendingMACKey;
        }

        sendingMACKey = OtrCryptoEngine.sha1Hash(getSendingAESKey());
        LOGGER.finest("Calculated sending MAC key.");
        return sendingMACKey;
    }

    byte[] getReceivingMACKey() throws OtrException {
        if (receivingMACKey == null) {
            receivingMACKey = OtrCryptoEngine.sha1Hash(getReceivingAESKey());
            LOGGER.finest("Calculated receiving MAC key.");
        }
        return receivingMACKey;
    }

    void setIsUsedReceivingMACKey(final boolean isUsedReceivingMACKey) {
        this.isUsedReceivingMACKey = isUsedReceivingMACKey;
    }

    boolean getIsUsedReceivingMACKey() {
        return isUsedReceivingMACKey;
    }

    int getLocalKeyID() {
        return localKeyID;
    }

    int getRemoteKeyID() {
        return remoteKeyID;
    }

    DHPublicKey getRemoteKey() {
        return remoteKey;
    }

    KeyPair getLocalPair() {
        return localPair;
    }
}
