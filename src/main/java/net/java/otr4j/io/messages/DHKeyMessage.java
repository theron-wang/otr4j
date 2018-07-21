/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.Objects;

/**
 * OTRv2 AKE DH-Key message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// FIXME add exact protocol version checks for OTRv2/OTRv3 message types.
public final class DHKeyMessage extends AbstractEncodedMessage {

    static final int MESSAGE_DHKEY = 0x0a;

    public final DHPublicKey dhPublicKey;

    public DHKeyMessage(final int protocolVersion, @Nonnull final DHPublicKey dhPublicKey, final int senderInstance, final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.dhPublicKey = Objects.requireNonNull(dhPublicKey);
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
        final DHKeyMessage other = (DHKeyMessage) obj;
        if (dhPublicKey == null) {
            if (other.dhPublicKey != null) {
                return false;
            }
        } else if (dhPublicKey.getY().compareTo(other.dhPublicKey.getY()) != 0) {
            return false;
        }
        return true;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeDHPublicKey(this.dhPublicKey);
    }

    @Override
    public int getType() {
        return MESSAGE_DHKEY;
    }
}
