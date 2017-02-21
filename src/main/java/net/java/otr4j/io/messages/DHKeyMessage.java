/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import java.util.Objects;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;

/**
 * 
 * @author George Politis
 * @author Danny van Heumen
 */
public final class DHKeyMessage extends AbstractEncodedMessage {

    public final DHPublicKey dhPublicKey;

    public DHKeyMessage(final int protocolVersion, @Nonnull final DHPublicKey dhPublicKey) {
        this(protocolVersion, dhPublicKey, 0, 0);
    }

    public DHKeyMessage(final int protocolVersion, @Nonnull final DHPublicKey dhPublicKey, final int senderInstance, final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.dhPublicKey = Objects.requireNonNull(dhPublicKey);
    }

    @Override
    public int getType() {
        return Message.MESSAGE_DHKEY;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result
				+ ((dhPublicKey == null) ? 0 : dhPublicKey.hashCode());
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
		DHKeyMessage other = (DHKeyMessage) obj;
		if (dhPublicKey == null) {
			if (other.dhPublicKey != null) {
                return false;
            }
		} else if (dhPublicKey.getY().compareTo(other.dhPublicKey.getY()) != 0) {
            return false;
        }
		return true;
	}
}
