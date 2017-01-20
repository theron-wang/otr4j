/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import java.util.Arrays;

/**
 *
 * @author George Politis
 */
public class SignatureMessage extends AbstractEncodedMessage {
	// Fields.
	public byte[] xEncrypted;
	public byte[] xEncryptedMAC;

    // Ctor.
    public SignatureMessage(final int protocolVersion, final byte[] xEncrypted,
            final byte[] xEncryptedMAC) {
        this(MESSAGE_SIGNATURE, protocolVersion, xEncrypted, xEncryptedMAC, 0, 0);
    }

    public SignatureMessage(final int protocolVersion, final byte[] xEncrypted,
            final byte[] xEncryptedMAC, final int senderInstance,
            final int receiverInstance) {
        this(MESSAGE_SIGNATURE, protocolVersion, xEncrypted, xEncryptedMAC,
                senderInstance, receiverInstance);
    }

    protected SignatureMessage(final int messageType, final int protocolVersion,
            final byte[] xEncrypted, final byte[] xEncryptedMAC) {
        this(messageType, protocolVersion, xEncrypted, xEncryptedMAC, 0, 0);
    }

    protected SignatureMessage(final int messageType, final int protocolVersion,
            final byte[] xEncrypted, final byte[] xEncryptedMAC,
            final int senderInstance, final int receiverInstance) {
        super(messageType, protocolVersion, senderInstance, receiverInstance);
        this.xEncrypted = xEncrypted;
        this.xEncryptedMAC = xEncryptedMAC;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(xEncrypted);
		result = prime * result + Arrays.hashCode(xEncryptedMAC);
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
		SignatureMessage other = (SignatureMessage) obj;
		if (!Arrays.equals(xEncrypted, other.xEncrypted)) {
            return false;
        }
		if (!Arrays.equals(xEncryptedMAC, other.xEncryptedMAC)) {
            return false;
        }
		return true;
	}
}
