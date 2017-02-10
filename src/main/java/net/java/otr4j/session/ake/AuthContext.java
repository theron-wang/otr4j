package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.SecureRandom;
import javax.annotation.Nonnull;

public interface AuthContext {

    /**
     * Update AKE state in context.
     *
     * @param state The new AKE state.
     */
    void setState(@Nonnull AuthState state);

    /**
     * Transition to a message state ENCRYPTED based on the provided parameters.
     *
     * @param params Instance containing all parameters that are negotiated
     * during the AKE that are relevant to setting up and maintaining the
     * encrypted message state.
     * @throws InteractionFailedException Thrown in case transition into
     * ENCRYPTED message state fails.
     */
    void secure(SecurityParameters params) throws InteractionFailedException;

    /**
     * Access to SecureRandom instance.
     *
     * @return Returns SecureRandom instance.
     */
    @Nonnull
    SecureRandom secureRandom();

    /**
     * Access to long-term key pair.
     *
     * @return Returns long-term key pair.
     */
    @Nonnull
    // FIXME rename to match methods from session.State.
    KeyPair longTermKeyPair();

    /**
     * Sender instance tag value.
     *
     * @return Returns sender instance tag value.
     */
    // FIXME rename to match methods from session.State.
    int senderInstance();

    /**
     * Receiver instance tag value.
     *
     * @return Returns recipient instance tag value.
     */
    // FIXME rename to match methods from session.State.
    int receiverInstance();

    /**
     * InteractionFailedException indicates an error happened while interacting
     * with AKE's context.
     *
     * This exception is defined for users of the ake package, i.e. AuthContext
     * implementors, such that they can throw an exception in case of failure.
     * InteractionFailedException is the only recognized checked exception which
     * the ake package takes into account inside the implementation logic.
     */
    final class InteractionFailedException extends Exception {

        private static final long serialVersionUID = -8731442427746963923L;

        public InteractionFailedException(@Nonnull final Throwable cause) {
            super(cause);
        }
    }
}
