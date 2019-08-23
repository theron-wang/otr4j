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
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireInRange;
import static net.java.otr4j.util.Objects.requireNotEquals;

/**
 * OTRv4 Interactive DAKE Identity Message.
 *
 * The identity message is used to send initial identity information upon establishing a new session.
 */
public final class IdentityMessage extends AbstractEncodedMessage {

    /**
     * Byte code identifier for Identity message type.
     */
    static final int MESSAGE_IDENTITY = 0x35;

    /**
     * Client profile (as payload).
     */
    @Nonnull
    public final ClientProfilePayload clientProfile;

    /**
     * ECDH public key 'Y'.
     */
    @Nonnull
    public final Point y;

    /**
     * DH public key 'B'.
     */
    @Nonnull
    public final BigInteger b;

    /**
     * The first ECDH public key to be used after DAKE completes.
     */
    @Nonnull
    public final Point ourFirstECDHPublicKey;

    /**
     * The first DH public key to be used after DAKE completes.
     */
    @Nonnull
    public final BigInteger ourFirstDHPublicKey;

    /**
     * Identity message type of OTRv4.
     *
     * @param protocolVersion       the protocol version
     * @param senderInstance        the sender instance tag
     * @param receiverInstance      the receiver instance tag
     * @param clientProfile         the client profile (as payload)
     * @param y                     the ECDH public key 'Y'
     * @param b                     the DH public key 'B'
     * @param ourFirstECDHPublicKey the first ECDH public key to be used after DAKE completes
     * @param ourFirstDHPublicKey   the first DH public key to be used after DAKE completes
     */
    public IdentityMessage(final int protocolVersion, final InstanceTag senderInstance,
            final InstanceTag receiverInstance, final ClientProfilePayload clientProfile, final Point y,
            final BigInteger b, final Point ourFirstECDHPublicKey, final BigInteger ourFirstDHPublicKey) {
        super(requireInRange(Version.FOUR, Version.FOUR, protocolVersion), senderInstance, receiverInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourFirstECDHPublicKey = requireNonNull(ourFirstECDHPublicKey);
        this.ourFirstDHPublicKey = requireNonNull(ourFirstDHPublicKey);
        requireNotEquals(this.y, this.ourFirstECDHPublicKey, "Y cannot be the same as first ECDH public key.");
        requireNotEquals(this.b, this.ourFirstDHPublicKey, "B cannot be the same as first DH public key.");
    }

    @Override
    public int getType() {
        return MESSAGE_IDENTITY;
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(clientProfile);
        writer.writePoint(this.y);
        writer.writeBigInt(this.b);
        writer.writePoint(this.ourFirstECDHPublicKey);
        writer.writeBigInt(this.ourFirstDHPublicKey);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        final IdentityMessage that = (IdentityMessage) o;
        return clientProfile.equals(that.clientProfile) && y.constantTimeEquals(that.y) && b.equals(that.b)
                && ourFirstECDHPublicKey.constantTimeEquals(that.ourFirstECDHPublicKey)
                && ourFirstDHPublicKey.equals(that.ourFirstDHPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), clientProfile, y, b, ourFirstECDHPublicKey, ourFirstDHPublicKey);
    }
}
