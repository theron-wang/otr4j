/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import java.util.Arrays;
import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * 
 * @author George Politis
 * @author Danny van Heumen
 */
public class RevealSignatureMessage extends SignatureMessage {

    public final byte[] revealedKey;

    public RevealSignatureMessage(final int protocolVersion,
            @Nonnull final byte[] xEncrypted,
            @Nonnull final byte[] xEncryptedMAC,
            @Nonnull final byte[] revealedKey) {
        super(protocolVersion, xEncrypted, xEncryptedMAC);
        this.revealedKey = Objects.requireNonNull(revealedKey);
    }

    public RevealSignatureMessage(final int protocolVersion,
            @Nonnull final byte[] xEncrypted,
            @Nonnull final byte[] xEncryptedMAC,
            @Nonnull final byte[] revealedKey,
            final int senderInstance,
            final int receiverInstance) {
        super(protocolVersion, xEncrypted, xEncryptedMAC, senderInstance, receiverInstance);
        this.revealedKey = Objects.requireNonNull(revealedKey);
    }

    @Override
    public int getType() {
        return Message.MESSAGE_REVEALSIG;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(revealedKey);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
            return true;
        }
		if (!super.equals(obj)) {
            return false;
        }
		if (getClass() != obj.getClass()) {
            return false;
        }
		RevealSignatureMessage other = (RevealSignatureMessage) obj;
		if (!Arrays.equals(revealedKey, other.revealedKey)) {
            return false;
        }
		return true;
	}
}
