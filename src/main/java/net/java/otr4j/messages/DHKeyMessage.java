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
import javax.crypto.interfaces.DHPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv2 AKE DH-Key message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class DHKeyMessage extends AbstractEncodedMessage {

    /**
     * Byte code identifier for DH-Key message type.
     */
    static final int MESSAGE_DHKEY = 0x0a;

    /**
     * DH public key.
     */
    @Nonnull
    public final DHPublicKey dhPublicKey;

    /**
     * Constructor.
     *
     * @param protocolVersion  the protcol version
     * @param dhPublicKey      the DH public key
     * @param senderInstance   the sender instance tag
     * @param receiverInstance the receiver instance tag
     */
    public DHKeyMessage(final int protocolVersion, final DHPublicKey dhPublicKey, final InstanceTag senderInstance,
            final InstanceTag receiverInstance) {
        super(requireInRange(Version.TWO, Version.THREE, protocolVersion), senderInstance, receiverInstance);
        this.dhPublicKey = requireNonNull(dhPublicKey);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + dhPublicKey.hashCode();
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
        return dhPublicKey.getY().compareTo(other.dhPublicKey.getY()) == 0;
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeDHPublicKey(this.dhPublicKey);
    }

    @Override
    public int getType() {
        return MESSAGE_DHKEY;
    }
}
