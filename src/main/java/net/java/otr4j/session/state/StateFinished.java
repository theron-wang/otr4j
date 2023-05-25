/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OtrEngineHosts.finishedSessionMessage;
import static net.java.otr4j.api.OtrEngineHosts.unencryptedMessageReceived;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;

/**
 * Message state FINISHED. This message state is initiated through events started from the initial message state
 * PLAINTEXT (and transition through ENCRYPTED).
 *
 * @author Danny van Heumen
 */
final class StateFinished extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateFinished.class.getName());

    private static final SessionStatus STATUS = SessionStatus.FINISHED;

    StateFinished(final AuthState authState) {
        super(authState);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() throws IncorrectStateException {
        throw new IncorrectStateException("No OTR session is established yet.");
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in finished state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in finished state.");
    }

    @Override
    @Nonnull
    public Result handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), context.getSessionID(), message.getCleanText());
        return new Result(STATUS, message.getCleanText());
    }

    // TODO currently `StateFinished` is shared among OTRv2/3/4. In OTRv4 spec, separate `FINISHED` states exist for OTRv3 and OTRv4. Consider separating as well. (Needed to prevent subtle switching from OTR 4 to OTR 3 with intermediate FINISHED.)
    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final EncodedMessage message) throws ProtocolException, OtrException {
        switch (message.version) {
        case Session.Version.ONE:
            LOGGER.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, null);
        case Session.Version.TWO:
        case Session.Version.THREE:
            return handleEncodedMessage3(context, message);
        case Session.Version.FOUR:
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.version);
        }
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException {
        if (message instanceof IdentityMessage) {
            try {
                handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
            }
            return;
        }
        LOGGER.log(INFO, "We only expect to receive an Identity message. Ignoring message with messagetype: {0}",
                message.getType());
    }

    @Override
    @Nonnull
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv2/3 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, null);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, null);
    }

    @Override
    @Nullable
    public Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        context.queueMessage(msgText);
        finishedSessionMessage(context.getHost(), context.getSessionID(), msgText);
        return null;
    }

    @Override
    public void end(final Context context) {
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
