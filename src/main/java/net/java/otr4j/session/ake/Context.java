package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.SecureRandom;
import javax.annotation.Nonnull;

public interface Context {

    /**
     * Update AKE state in context.
     *
     * @param state The new AKE state.
     */
    void setState(@Nonnull State state);

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
     * Access to long-term keypair.
     *
     * @return Returns long-term keypair.
     */
    @Nonnull
    KeyPair longTermKeyPair();

    /**
     * Sender instance tag value.
     *
     * @return Returns sender instance tag value.
     */
    int senderInstance();

    /**
     * Receiver instance tag value.
     *
     * @return Returns recipient instance tag value.
     */
    int receiverInstance();

    /**
     * InteractionFailedException indicates an error happened while interacting
     * with AKE's context.
     */
    static final class InteractionFailedException extends Exception {

        private static final long serialVersionUID = -8731442427746963923L;

        public InteractionFailedException(@Nonnull final Throwable cause) {
            super(cause);
        }
    }
}
