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
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * OTRv2/OTRv3 AKE Signature message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class SignatureMessage extends AbstractEncodedMessage {

    static final int MESSAGE_SIGNATURE = 0x12;

    /**
     * Encrypted X.
     */
    @Nonnull
    public final byte[] xEncrypted;
    /**
     * MAC of encrypted X.
     */
    @Nonnull
    public final byte[] xEncryptedMAC;

    /**
     * Constructor.
     *
     * @param protocolVersion  the protocol version
     * @param xEncrypted       encrypted X
     * @param xEncryptedMAC    MAC of encrypted X
     * @param senderInstance   sender instance tag
     * @param receiverInstance receiver instance tag
     */
    public SignatureMessage(final Version protocolVersion, final byte[] xEncrypted, final byte[] xEncryptedMAC,
            final InstanceTag senderInstance, final InstanceTag receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        if (protocolVersion != Version.TWO && protocolVersion != Version.THREE) {
            throw new IllegalArgumentException("Illegal version");
        }
        this.xEncrypted = requireNonNull(xEncrypted);
        this.xEncryptedMAC = requireNonNull(xEncryptedMAC);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(this.xEncrypted);
        result = prime * result + Arrays.hashCode(this.xEncryptedMAC);
        return result;
    }

    @SuppressWarnings("ShortCircuitBoolean")
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignatureMessage other = (SignatureMessage) obj;
        return constantTimeEquals(this.xEncrypted, other.xEncrypted) & constantTimeEquals(this.xEncryptedMAC, other.xEncryptedMAC);
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.xEncrypted);
        writer.writeMac(this.xEncryptedMAC);
    }

    @Override
    public int getType() {
        return MESSAGE_SIGNATURE;
    }
}
