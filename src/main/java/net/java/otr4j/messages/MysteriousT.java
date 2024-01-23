/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.messages.DataMessage.MESSAGE_DATA;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * MysteriousT represents the T_a composite as described in "Exchanging Data" section.
 */
@SuppressWarnings("ClassNamedLikeTypeParameter")
public final class MysteriousT implements OtrEncodable {

    /**
     * The protocol version.
     */
    @Nonnull
    public final Version protocolVersion;
    /**
     * The sender instance tag.
     */
    @Nonnull
    public final InstanceTag senderInstanceTag;
    /**
     * The receiver instance tag.
     */
    @Nonnull
    public final InstanceTag receiverInstanceTag;
    /**
     * The message type.
     */
    public final int messageType;
    /**
     * The message flags.
     */
    public final byte flags;
    /**
     * The sender key ID.
     */
    public final int senderKeyID;
    /**
     * The receiver key ID.
     */
    public final int recipientKeyID;
    /**
     * The next DH public key.
     */
    @Nonnull
    public final DHPublicKey nextDH;
    /**
     * The counter value used in the message.
     */
    public final byte[] ctr;
    /**
     * The encrypted message content.
     */
    public final byte[] encryptedMessage;

    /**
     * Constructor for MysteriousT.
     *
     * @param protocolVersion     the protocol version
     * @param senderInstanceTag   the sender instance tag
     * @param receiverInstanceTag the receiver instance tag
     * @param flags               message flags
     * @param senderKeyID         the sender key ID
     * @param recipientKeyID      the receiver key ID
     * @param nextDH              the next DH public key
     * @param ctr                 the counter value used in the message
     * @param encryptedMessage    the encrypted message content
     */
    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    public MysteriousT(final Version protocolVersion, final InstanceTag senderInstanceTag,
            final InstanceTag receiverInstanceTag, final byte flags, final int senderKeyID, final int recipientKeyID,
            final DHPublicKey nextDH, final byte[] ctr, final byte[] encryptedMessage) {
        if (protocolVersion != Version.TWO && protocolVersion != Version.THREE) {
            throw new IllegalArgumentException("Illegal protocol version specified.");
        }
        this.protocolVersion = requireNonNull(protocolVersion);
        this.senderInstanceTag = requireNonNull(senderInstanceTag);
        this.receiverInstanceTag = requireNonNull(receiverInstanceTag);
        this.messageType = MESSAGE_DATA;
        this.flags = flags;
        this.senderKeyID = senderKeyID;
        this.recipientKeyID = recipientKeyID;
        this.nextDH = nextDH;
        this.ctr = ctr;
        this.encryptedMessage = encryptedMessage;
    }

    // Methods.
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(this.ctr);
        result = prime * result + Arrays.hashCode(this.encryptedMessage);
        result = prime * result + this.flags;
        result = prime * result + this.messageType;
        result = prime * result + this.nextDH.hashCode();
        result = prime * result + this.protocolVersion.hashCode();
        result = prime * result + this.recipientKeyID;
        result = prime * result + this.senderKeyID;
        result = prime * result + this.senderInstanceTag.hashCode();
        result = prime * result + this.receiverInstanceTag.hashCode();
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final MysteriousT other = (MysteriousT) obj;
        if (!constantTimeEquals(this.ctr, other.ctr)) {
            return false;
        }
        if (!constantTimeEquals(this.encryptedMessage, other.encryptedMessage)) {
            return false;
        }
        if (this.flags != other.flags) {
            return false;
        }
        if (this.messageType != other.messageType) {
            return false;
        }
        if (!this.nextDH.equals(other.nextDH)) {
            return false;
        }
        if (this.protocolVersion != other.protocolVersion) {
            return false;
        }
        if (this.recipientKeyID != other.recipientKeyID) {
            return false;
        }
        if (this.senderKeyID != other.senderKeyID) {
            return false;
        }
        if (!this.senderInstanceTag.equals(other.senderInstanceTag)) {
            return false;
        }
        return this.receiverInstanceTag.equals(other.receiverInstanceTag);
    }

    @Override
    public void writeTo(final OtrOutputStream out) {
        out.writeShort(this.protocolVersion.ordinal());
        out.writeByte(this.messageType);
        if (this.protocolVersion == Version.THREE) {
            out.writeInstanceTag(this.senderInstanceTag);
            out.writeInstanceTag(this.receiverInstanceTag);
        }
        out.writeByte(this.flags);
        out.writeInt(this.senderKeyID);
        out.writeInt(this.recipientKeyID);
        out.writeDHPublicKey(this.nextDH);
        out.writeCtr(this.ctr);
        out.writeData(this.encryptedMessage);
    }
}
