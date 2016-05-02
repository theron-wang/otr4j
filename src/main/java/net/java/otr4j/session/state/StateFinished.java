package net.java.otr4j.session.state;

import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.SmpTlvHandler;
import net.java.otr4j.session.TLV;

public final class StateFinished extends AbstractState {

    @SuppressWarnings("NonConstantLogger")
    private final Logger logger;
    private final SessionID sessionId;

    StateFinished(final SessionID sessionId) {
        // FIXME Identify session state in logger
        this.logger = Logger.getLogger(sessionId.getAccountID() + "-->" + sessionId.getUserID());
        this.sessionId = Objects.requireNonNull(sessionId);
    }

    @Override
    @Nonnull
    public SessionID getSessionId() {
        return this.sessionId;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.FINISHED;
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpTlvHandler() {
        // FIXME consider checked exception since this can happen without programmer's fault in real life situation
        throw new IllegalStateException("SmpTlvHandler not available in finished state.");
    }

    @Override
    @Nonnull
    public PublicKey getRemotePublicKey() {
        // TODO How to handle this? We could preserve public key for now so that we can answer this request. Or we could throw a checked exception, since this is case could reasonably happen.
        throw new IllegalStateException("Encrypted session has been finished by other party.");
    }

    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) throws OtrException {
        // Display the message to the user, but warn him that the message was
        // received unencrypted.
        OtrEngineHostUtil.unencryptedMessageReceived(context.getHost(),
                sessionId, plainTextMessage.cleanText);
        return plainTextMessage.cleanText;
    }

    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws OtrException {
        final OtrEngineHost host = context.getHost();
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
        final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
        context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
        return null;
    }

    @Override
    @Nonnull
    public String[] transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        OtrEngineHostUtil.finishedSessionMessage(context.getHost(), sessionId, msgText);
        return new String[0];
    }

    @Override
    public void secure(@Nonnull final Context context) throws OtrException {
        context.setState(new StateEncrypted(context, this.sessionId));
    }

    @Override
    public void end(@Nonnull final Context context) {
        context.setState(new StatePlaintext(this.sessionId));
    }
}
