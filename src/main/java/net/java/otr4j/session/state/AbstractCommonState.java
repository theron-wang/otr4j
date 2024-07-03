/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.Event;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nullable;
import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;

abstract class AbstractCommonState extends AbstractOTR4State {

    private static final Logger LOGGER = Logger.getLogger(AbstractCommonState.class.getName());

    AbstractCommonState(final AuthState authState) {
        super(authState);
    }

    @Override
    public void handleErrorMessage(final Context context, final ErrorMessage errorMessage) throws OtrException {
        handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                Event.ERROR, "OTR error: " + errorMessage.error);
    }

    void handleUnreadableMessage(final Context context, final DataMessage message, final String identifier,
            final String error) throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, identifier, error);
    }

    void handleUnreadableMessage(final Context context, final DataMessage4 message, final String identifier,
            final String error) throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            // TODO consider detecting (and logging) whether revealed MAC-keys are non-empty. This concerns the issue with OTRv4 (also v3?) spec which mentions that when the other party receives a DISCONNECT-TLV, they end the session, but this means that they do not reveal present MAC keys to be revealed of our previous messages. Logging this allows us to check that the other party acts properly. That is, if we accept that as part of the spec.
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, identifier, error);
    }

    /**
     * Implementation of {@code transformSending(Context, String, List, byte)} that prevents sending messages as we have
     * not yet transitioned into `ENCRYPTED_MESSAGES` state.
     *
     * @param context The message state context.
     * @param msgText The message to be sent.
     * @param tlvs    List of TLVs to attach to the message.
     * @param flags   (Encoded) message flags, see constants in {@link State}, such as {@link #FLAG_IGNORE_UNREADABLE}.
     * @return Returns null as there is nothing to send immediately.
     * @throws OtrException In case an exception occurs.
     */
    @Nullable
    @Override
    public Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) throws OtrException {
        handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                Event.ENCRYPTED_MESSAGES_REQUIRED, msgText);
        return null;
    }

    @Override
    public void expire(final Context context) throws OtrException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    @Override
    public long getLastActivityTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    @Override
    public long getLastMessageSentTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " is not an encrypted state.");
    }
}
