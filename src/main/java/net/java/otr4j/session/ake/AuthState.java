package net.java.otr4j.session.ake;

import java.io.IOException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;

/**
 * Interface for the AKE states.
 *
 * This interface defines the methods that need to be implemented. Implementors
 * are expected to be immutable. That is, they may receive some support data at
 * construction time, but they are not supposed to mutate data inside. Instead,
 * for each receiving message, which should entail a state transition, we should
 * instantiate a new state with the appropriate set of initial data.
 *
 * @author Danny van Heumen
 */
public interface AuthState {

    /**
     * Initiate a new AKE. Caller needs to send
     *
     * @param context Context.
     * @param version Initiate AKE using protocol version.
     * @return Returns DHCommitMessage with which we can initiate an AKE.
     */
    @Nonnull
    DHCommitMessage initiate(@Nonnull AuthContext context, int version);

    /**
     * Handle AKE message.
     *
     * @param context The current AKE context.
     * @param message The message to be handled.
     * @return Returns message to be injected into the transport stream to
     * continue the AKE process. In case of 'null' no message needs to be
     * injected after handling this message.
     * @throws IOException Throws exception in case of bad message content.
     * (Note that an AbstractEncodedMessage instance is provided, so failures
     * should only occur based on bad message content.)
     * @throws OtrCryptoException Throws OtrCryptoException in case of
     * unexpected situations during message processing, such as validation
     * exceptions.
     * @throws AuthContext.InteractionFailedException Thrown in case of failure
     * while interacting with the provided AKE context.
     */
    @Nullable
    AbstractEncodedMessage handle(@Nonnull AuthContext context, @Nonnull AbstractEncodedMessage message) throws IOException, OtrCryptoException, AuthContext.InteractionFailedException;

    /**
     * Get active protocol version in AKE negotiation.
     *
     * @return Returns active protocol version in AKE negotiation.
     */
    // FIXME what do we return in the initial state, as a version is yet to be declared at that point?
    int getVersion();
}
