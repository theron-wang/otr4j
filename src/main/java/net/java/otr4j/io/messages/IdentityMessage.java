package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.profile.ClientProfiles.writeTo;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Identity Message.
 *
 * The identity message is used to send initial identity information upon establishing a new session.
 */
public final class IdentityMessage extends AbstractEncodedMessage {

    // OTRv4 Encoded message types
    static final int MESSAGE_IDENTITY = 0x08;

    private final ClientProfile clientProfile;
    private final Point y;
    private final BigInteger b;

    // FIXME need to do additional validation for values being injected in constructor?
    public IdentityMessage(final int protocolVersion, final int senderInstance, final int receiverInstance,
                           @Nonnull final ClientProfile clientProfile, @Nonnull final Point y, @Nonnull final BigInteger b) {
        super(requireAtLeast(4, protocolVersion), senderInstance, receiverInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
    }

    @Override
    public int getType() {
        return MESSAGE_IDENTITY;
    }

    @Nonnull
    public ClientProfile getClientProfile() {
        return clientProfile;
    }

    @Nonnull
    public Point getY() {
        return y;
    }

    @Nonnull
    public BigInteger getB() {
        return b;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        clientProfile.writeTo(writer);
        writer.writePoint(this.y);
        writer.writeBigInt(this.b);
    }
}
