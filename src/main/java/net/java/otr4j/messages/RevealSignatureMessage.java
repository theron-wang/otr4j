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
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv2 AKE Reveal Signature message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class RevealSignatureMessage extends AbstractEncodedMessage {

    static final int MESSAGE_REVEALSIG = 0x11;

    /**
     * The revealed key.
     */
    @Nonnull
    public final byte[] revealedKey;
    /**
     * Encrypted value 'x'.
     */
    @Nonnull
    public final byte[] xEncrypted;
    /**
     * MAC of encrypted value 'x'.
     */
    @Nonnull
    public final byte[] xEncryptedMAC;

    /**
     * Constructor for Reveal Signature message.
     *
     * @param protocolVersion  the protocol version
     * @param xEncrypted       encrypted value 'x'
     * @param xEncryptedMAC    MAC of encrypted value 'x'
     * @param revealedKey      revealed key (for decrypting sent key)
     * @param senderInstance   the sender instance tag
     * @param receiverInstance the receiver instance tag
     */
    public RevealSignatureMessage(final int protocolVersion, final byte[] xEncrypted, final byte[] xEncryptedMAC,
            final byte[] revealedKey, final InstanceTag senderInstance, final InstanceTag receiverInstance) {
        super(requireInRange(Version.TWO, Version.THREE, protocolVersion), senderInstance, receiverInstance);
        this.xEncrypted = requireNonNull(xEncrypted);
        this.xEncryptedMAC = requireNonNull(xEncryptedMAC);
        this.revealedKey = requireNonNull(revealedKey);
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.revealedKey);
        writer.writeData(this.xEncrypted);
        writer.writeMac(this.xEncryptedMAC);
    }

    @Override
    public int getType() {
        return MESSAGE_REVEALSIG;
    }

    @SuppressWarnings("ShortCircuitBoolean")
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!super.equals(o)) {
            return false;
        }
        if (getClass() != o.getClass()) {
            return false;
        }
        final RevealSignatureMessage that = (RevealSignatureMessage) o;
        return constantTimeEquals(revealedKey, that.revealedKey) & constantTimeEquals(xEncrypted, that.xEncrypted)
                & constantTimeEquals(xEncryptedMAC, that.xEncryptedMAC);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(revealedKey);
        result = 31 * result + Arrays.hashCode(xEncrypted);
        result = 31 * result + Arrays.hashCode(xEncryptedMAC);
        return result;
    }
}
