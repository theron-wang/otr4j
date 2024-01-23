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
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * The OTRv4 data message.
 */
public final class DataMessage4 extends AbstractEncodedMessage {

    static final int MESSAGE_DATA = 0x03;

    /**
     * Message flags.
     */
    public final byte flags;

    /**
     * Number of messages in previous ratchet.
     */
    public final int pn;

    /**
     * Ratchet ID.
     */
    public final int i;

    /**
     * Message ID.
     */
    public final int j;

    /**
     * The ECDH public key.
     */
    @Nonnull
    public final Point ecdhPublicKey;

    /**
     * The DH public key.
     */
    @Nullable
    public final BigInteger dhPublicKey;

    /**
     * Ciphertext contained in the data message.
     */
    @Nonnull
    public final byte[] ciphertext;

    /**
     * The authenticator for the data message.
     */
    @Nonnull
    public final byte[] authenticator;

    /**
     * Revealed MAC codes as a byte-array.
     */
    @Nonnull
    public final byte[] revealedMacs;

    /**
     * Construct a new instance of DataMessage4 with the authenticator replaced by the provided one.
     *
     * @param original      the original DataMessage4 instance
     * @param authenticator the substitute authenticator
     */
    public DataMessage4(final DataMessage4 original, final byte[] authenticator) {
        this(original.senderTag, original.receiverTag, original.flags, original.pn, original.i, original.j,
                original.ecdhPublicKey, original.dhPublicKey, original.ciphertext, authenticator,
                original.revealedMacs);
    }

    /**
     * Constructor for the data message.
     *
     * @param senderInstanceTag   the sender instance tag
     * @param receiverInstanceTag the receiver instance tag
     * @param flags               the message flags
     * @param pn                  the number of messages in previous ratchet
     * @param i                   the ratchet ID
     * @param j                   the message ID
     * @param ecdhPublicKey       the ECDH public key
     * @param dhPublicKey         the DH public key (is only present every third ratchet)
     * @param ciphertext          the ciphertext
     * @param authenticator       the authenticator code
     * @param revealedMacs        the revealed MAC keys
     */
    public DataMessage4(final InstanceTag senderInstanceTag, final InstanceTag receiverInstanceTag, final byte flags,
            final int pn, final int i, final int j, final Point ecdhPublicKey, @Nullable final BigInteger dhPublicKey,
            final byte[] ciphertext, final byte[] authenticator, final byte[] revealedMacs) {
        super(Version.FOUR, senderInstanceTag, receiverInstanceTag);
        this.flags = flags;
        this.pn = pn;
        this.i = i;
        this.j = j;
        this.ecdhPublicKey = requireNonNull(ecdhPublicKey);
        this.dhPublicKey = dhPublicKey;
        this.ciphertext = requireNonNull(ciphertext);
        this.authenticator = requireLengthExactly(AUTHENTICATOR_LENGTH_BYTES, authenticator);
        this.revealedMacs = requireNonNull(revealedMacs);
    }

    @Override
    public int getType() {
        return MESSAGE_DATA;
    }

    @SuppressWarnings("ConstantValue")
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        final DataMessage4 that = (DataMessage4) o;
        return this.flags == that.flags && this.pn == that.pn && this.i == that.i && this.j == that.j
                && Objects.equals(this.ecdhPublicKey, that.ecdhPublicKey)
                && Objects.equals(this.dhPublicKey, that.dhPublicKey)
                && constantTimeEquals(this.ciphertext, that.ciphertext)
                && constantTimeEquals(this.authenticator, that.authenticator)
                // Note: revealed MACs are not sensitive, so there is no sense in comparing constant-time
                && Arrays.equals(this.revealedMacs, that.revealedMacs);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), this.flags, this.pn, this.i, this.j, this.ecdhPublicKey, this.dhPublicKey);
        result = 31 * result + Arrays.hashCode(this.ciphertext);
        result = 31 * result + Arrays.hashCode(this.authenticator);
        result = 31 * result + Arrays.hashCode(this.revealedMacs);
        return result;
    }

    @SuppressWarnings({"MethodDoesntCallSuperMethod", "MissingSuperCall"})
    @Override
    public void writeTo(final OtrOutputStream writer) {
        // Intentionally not calling `super.writeTo(writer)`. It is already called in `writeDataMessageSections`.
        writeDataMessageSections(writer);
        assert !allZeroBytes(this.authenticator) : "BUG: the chance for an all zero-bytes authenticator is extremely low. Verify if the authenticator is embedded into the message after it has been generated.";
        writer.writeMacOTR4(this.authenticator);
        writer.writeData(this.revealedMacs);
    }

    /**
     * Write the first part of the Data message.
     *
     * @param writer the output stream to write to.
     */
    void writeDataMessageSections(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeByte(this.flags);
        writer.writeInt(this.pn);
        writer.writeInt(this.i);
        writer.writeInt(this.j);
        writer.writePoint(this.ecdhPublicKey);
        if (this.dhPublicKey == null) {
            writer.writeData(new byte[0]);
        } else {
            writer.writeBigInt(this.dhPublicKey);
        }
        writer.writeData(this.ciphertext);
    }
}
