package net.java.otr4j.session.state;

import java.security.PublicKey;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.java.otr4j.OtrException;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

public interface State {

    /**
     * Get session ID.
     *
     * @return Returns session ID.
     */
    @Nonnull
    SessionID getSessionID();

    /**
     * Get session status for currently active session.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getStatus();

    /**
     * Get remote public key.
     *
     * @return Returns the remote public key.
     * @throws net.java.otr4j.session.state.State.IncorrectStateException Throws
     * IncorrectStateException in any non-encrypted state, since no public key
     * is available there.
     */
    @Nonnull
    PublicKey getRemotePublicKey() throws IncorrectStateException;

    /**
     * Transforms a message ready to be sent given the current session state of
     * OTR.
     *
     * @param context The session context.
     * @param msgText The message ready to be sent.
     * @param tlvs List of TLVs.
     * @return Returns array of message fragments ready to be sent over IM
     * transport.
     * @throws OtrException In case an exception occurs.
     */
    @Nonnull
    String[] transformSending(@Nonnull Context context, @Nonnull String msgText, @Nonnull List<TLV> tlvs) throws OtrException;

    /**
     * Handle the received plaintext message.
     *
     * @param context The session context.
     * @param plainTextMessage The received plaintext message.
     * @return Returns the cleaned plaintext message. (The message excluding
     * possible whitespace tags or other OTR artifacts.)
     * @throws OtrException In case an exception occurs.
     */
    @Nonnull
    String handlePlainTextMessage(@Nonnull Context context, @Nonnull PlainTextMessage plainTextMessage) throws OtrException;

    /**
     * Handle the received data message.
     *
     * @param context The session context.
     * @param message The received message.
     * @return Returns the decrypted message context.
     * @throws OtrException In case an exception occurs.
     */
    @Nullable
    String handleDataMessage(@Nonnull Context context, @Nonnull DataMessage message) throws OtrException;

    /**
     * Handle the received error message.
     *
     * @param context The session context.
     * @param errorMessage The error message.
     * @throws OtrException In case an exception occurs.
     */
    void handleErrorMessage(@Nonnull Context context, @Nonnull ErrorMessage errorMessage) throws OtrException;

    /**
     * Call to secure a session after a successful Authentication was performed.
     *
     * @param context The session context.
     * @throws OtrException In case an exception occurs.
     */
    void secure(@Nonnull Context context) throws OtrException;

    /**
     * Call to end encrypted session, if any.
     *
     * @param context The session context.
     * @throws OtrException In case an exception occurs.
     */
    void end(@Nonnull Context context) throws OtrException;

    /**
     * Get SMP TLV handler for use in SMP negotiations.
     *
     * The handler is only available in Encrypted states. In case another state
     * is active at time of calling, {@link IncorrectStateException} is thrown.
     *
     * @return Returns SMP TLV handler instance for this encrypted session.
     * @throws net.java.otr4j.session.state.State.IncorrectStateException Throws
     * IncorrectStateException for any non-encrypted states.
     */
    @Nonnull
    SmpTlvHandler getSmpTlvHandler() throws IncorrectStateException;

    /**
     * Checked exception that is thrown for cases where the method call is not
     * appropriate. Given the nature of the protocol, state changes may happen
     * at any time. The nature of the checked exception can be used to handle
     * unexpected state transitions appropriately.
     */
    public class IncorrectStateException extends OtrException {

        private static final long serialVersionUID = -5335635776510194254L;

        public IncorrectStateException(final String message) {
            super(message);
        }
    }
}
