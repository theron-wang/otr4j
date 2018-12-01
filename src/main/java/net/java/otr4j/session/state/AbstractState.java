/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHostUtil.showError;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;

/**
 * Abstract base implementation for session state implementations.
 *
 * @author Danny van Heumen
 */
abstract class AbstractState implements State {

    // TODO is this "anonymous" logging an issue? (I.e. no session information in the log message.)
    private static final Logger LOGGER = Logger.getLogger(AbstractState.class.getName());

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        showError(context.getHost(), this.getSessionID(), errorMessage.error);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) throws OtrException {
        if ((message.getFlags() & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrCryptoException {
        context.transition(this, new StateEncrypted3(context, params));
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrException {
        final StateEncrypted4 encrypted = new StateEncrypted4(context, params);
        context.transition(this, encrypted);
        if (params.getInitializationComponent() == SecurityParameters4.Component.THEIRS) {
            LOGGER.log(Level.FINE, "We initialized THEIR component of the Double Ratchet, so it is complete. Sending heartbeat message.");
            context.injectMessage(encrypted.transformSending(context, "", Collections.<TLV>emptyList(),
                    FLAG_IGNORE_UNREADABLE));
        } else {
            LOGGER.log(Level.FINE, "We initialized OUR component of the Double Ratchet. We are still missing the other party's public key material, hence we cannot send messages yet. Now we wait to receive a message from the other party.");
        }
    }
}
