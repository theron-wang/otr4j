/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import java.io.IOException;
import java.util.Arrays;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.SerializationUtils;

/**
 *
 * @author George Politis
 */
public class SignatureMessage extends AbstractEncodedMessage {
	// Fields.
	public byte[] xEncrypted;
	public byte[] xEncryptedMAC;

	// Ctor.
	protected SignatureMessage(final int messageType, final int protocolVersion,
			final byte[] xEncrypted, final byte[] xEncryptedMAC) {
		super(messageType, protocolVersion);
		this.xEncrypted = xEncrypted;
		this.xEncryptedMAC = xEncryptedMAC;
	}

	public SignatureMessage(final int protocolVersion, final byte[] xEncrypted,
			final byte[] xEncryptedMAC) {
		this(MESSAGE_SIGNATURE, protocolVersion, xEncrypted, xEncryptedMAC);
	}

	// Memthods.
	public byte[] decrypt(final byte[] key) throws OtrException {
		return OtrCryptoEngine.aesDecrypt(key, null, xEncrypted);
	}

	public boolean verify(final byte[] key) throws OtrException {
		// Hash the key.
		final byte[] xbEncrypted;
		try {
			xbEncrypted = SerializationUtils.writeData(xEncrypted);
		} catch (IOException e) {
			throw new OtrException(e);
		}

		final byte[] xEncryptedMAC = OtrCryptoEngine.sha256Hmac160(
				xbEncrypted, key);
		// Verify signature.
		return Arrays.equals(this.xEncryptedMAC, xEncryptedMAC);
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
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignatureMessage other = (SignatureMessage) obj;
		if (!Arrays.equals(xEncrypted, other.xEncrypted))
			return false;
		if (!Arrays.equals(xEncryptedMAC, other.xEncryptedMAC))
			return false;
		return true;
	}
}
