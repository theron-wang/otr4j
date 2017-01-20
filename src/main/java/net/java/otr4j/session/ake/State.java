package net.java.otr4j.session.ake;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;

/**
 * Interface for the AKE states.
 *
 * @author Danny van Heumen
 */
public interface State {

    /**
     * Initiate a new AKE. Caller needs to send
     *
     * @param context Context.
     * @param version Initiate AKE using protocol version.
     * @return Returns DHCommitMessage with which we can initiate an AKE.
     */
    @Nonnull
    DHCommitMessage initiate(@Nonnull Context context, int version);

    /**
     * Handle AKE message.
     *
     * @param context The current AKE context.
     * @param message The message to be handled.
     * @return Returns message to be injected into the transport stream to
     * continue the AKE process. In case of 'null' no message needs to be
     * injected after handling this message.
     * @throws OtrCryptoException Throws OtrCryptoException in case of
     * unexpected situations during message processing, such as validation
     * exceptions.
     * @throws Context.InteractionFailedException Thrown in case of failure
     * while interacting with the provided AKE context.
     */
    @Nullable
    AbstractEncodedMessage handle(@Nonnull Context context, @Nonnull AbstractEncodedMessage message) throws OtrCryptoException, Context.InteractionFailedException;

    /**
     * Get active protocol version in AKE negotiation.
     *
     * @return Returns active protocol version in AKE negotiation.
     */
    int getVersion();
}
