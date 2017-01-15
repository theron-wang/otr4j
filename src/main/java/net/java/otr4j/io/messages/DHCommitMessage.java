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
public class DHCommitMessage extends AbstractEncodedMessage {

	// Fields.
	public byte[] dhPublicKeyEncrypted;
	public byte[] dhPublicKeyHash;

	// Ctor.
	public DHCommitMessage(final int protocolVersion, final byte[] dhPublicKeyHash,
			final byte[] dhPublicKeyEncrypted) {
        this(protocolVersion, dhPublicKeyHash, dhPublicKeyEncrypted, 0, 0);
	}

    public DHCommitMessage(final int protocolVersion, final byte[] dhPublicKeyHash,
            final byte[] dhPublicKeyEncrypted, final int senderInstance,
            final int receiverInstance) {
		super(MESSAGE_DH_COMMIT, protocolVersion, senderInstance, receiverInstance);
		this.dhPublicKeyEncrypted = dhPublicKeyEncrypted;
        // TODO consider verifying hash length as way of protecting against swapping hash and encrypted
		this.dhPublicKeyHash = dhPublicKeyHash;
    }
    
	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(dhPublicKeyEncrypted);
		result = prime * result + Arrays.hashCode(dhPublicKeyHash);
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
		DHCommitMessage other = (DHCommitMessage) obj;
		if (!Arrays.equals(dhPublicKeyEncrypted, other.dhPublicKeyEncrypted)) {
            return false;
        }
		if (!Arrays.equals(dhPublicKeyHash, other.dhPublicKeyHash)) {
            return false;
        }
		return true;
	}

}
