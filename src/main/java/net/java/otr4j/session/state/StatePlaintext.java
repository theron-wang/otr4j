/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyUtil;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.OfferStatus;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

public final class StatePlaintext extends AbstractState {

    private final SessionID sessionId;

    public StatePlaintext(final SessionID sessionId) {
        this.sessionId = Objects.requireNonNull(sessionId);
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionId;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.PLAINTEXT;
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpTlvHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in plaintext state.");
    }

    @Override
    @Nonnull
    public PublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in plaintext state.");
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
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) throws OtrException {
        // Simply display the message to the user. If REQUIRE_ENCRYPTION is set,
        // warn him that the message was received unencrypted.
        if (context.getSessionPolicy().getRequireEncryption()) {
            OtrEngineHostUtil.unencryptedMessageReceived(context.getHost(),
                    this.sessionId, plainTextMessage.cleanText);
        }
        return plainTextMessage.cleanText;
    }

    @Override
    @Nonnull
    public String[] transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        final OtrPolicy otrPolicy = context.getSessionPolicy();
        if (otrPolicy.getRequireEncryption()) {
            // Prevent original message from being sent. Start AKE.
            context.getAuthContext().startAuth();
            OtrEngineHostUtil.requireEncryptedMessage(context.getHost(), sessionId, msgText);
            return new String[0];
        }
        if (!otrPolicy.getSendWhitespaceTag()
                || context.getOfferStatus() == OfferStatus.rejected) {
            // As we do not want to send a specially crafted whitespace tag
            // message, just return the original message text to be sent.
            return new String[]{msgText};
        }
        // Continue with crafting a special whitespace message tag and embedding
        // it into the original message.
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(otrPolicy);
        if (versions.isEmpty()) {
            // Catch situation where we do not actually offer any versions.
            // At this point, reaching this state is considered a bug.
            throw new IllegalStateException("The current OTR policy does not allow any supported version of OTR. The software should either enable some protocol version or disable sending whitespace tags.");
        }
        final String message;
        try {
            message = SerializationUtils.toString(
                    new PlainTextMessage(versions, msgText));
        } catch (final IOException e) {
            throw new OtrException(e);
        }
        context.setOfferStatus(OfferStatus.sent);
        return new String[]{message};
    }

    @Override
    public void secure(@Nonnull final Context context) throws OtrException {
        context.setState(new StateEncrypted(context, this.sessionId));
    }

    @Override
    public void end(@Nonnull final Context context) {
        // already in "ended" state
    }
}
