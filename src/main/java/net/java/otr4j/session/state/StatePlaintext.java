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
            context.getAuthContext().startAuth();
            OtrEngineHostUtil.requireEncryptedMessage(context.getHost(), sessionId, msgText);
            return new String[0];
        }
        if (otrPolicy.getSendWhitespaceTag()
                && context.getOfferStatus() != OfferStatus.rejected) {
            // FIXME we should verify that we send a whitespace tag before assuming that the offer is sent. What happens if we have 0 versions left after checking policy. Do we still send a whitespace tag and how do we expect the counter party to respond? This is particularly tricky as we only offer the whitespace tag once, so we should know for sure that we offered it.
            context.setOfferStatus(OfferStatus.sent);
            final Set<Integer> versions = OtrPolicyUtil.allowedVersions(otrPolicy);
            final AbstractMessage abstractMessage = new PlainTextMessage(versions, msgText);
            try {
                return new String[]{
                    SerializationUtils.toString(abstractMessage)
                };
            } catch (final IOException e) {
                throw new OtrException(e);
            }
        }
        return new String[]{msgText};
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
