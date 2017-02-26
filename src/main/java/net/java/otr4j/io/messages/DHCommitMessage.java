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
public final class DHCommitMessage extends AbstractEncodedMessage {

    public final byte[] dhPublicKeyEncrypted;
    public final byte[] dhPublicKeyHash;

    public DHCommitMessage(final int protocolVersion,
            @Nonnull final byte[] dhPublicKeyHash,
            @Nonnull final byte[] dhPublicKeyEncrypted) {
        this(protocolVersion, dhPublicKeyHash, dhPublicKeyEncrypted, 0, 0);
    }

    public DHCommitMessage(final int protocolVersion,
            @Nonnull final byte[] dhPublicKeyHash,
            @Nonnull final byte[] dhPublicKeyEncrypted,
            final int senderInstance,
            final int receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        this.dhPublicKeyEncrypted = Objects.requireNonNull(dhPublicKeyEncrypted);
        this.dhPublicKeyHash = Objects.requireNonNull(dhPublicKeyHash);
    }

    @Override
    public int getType() {
        return Message.MESSAGE_DH_COMMIT;
    }
    
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
