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
import net.java.otr4j.session.SmpTlvHandler;
import net.java.otr4j.session.TLV;

/**
 *
 * @author danny
 */
public interface State {
    
    @Nonnull SessionID getSessionId();
    
    // TODO getStatus() should eventually be removed. After successful
    // refactoring we should not need to check the status anymore, since any
    // status-related actions are performed inside the state instances
    // themselves. However, that does mean that we have to move all
    // SMP interaction/SMP TLV handler too.
    @Nonnull SessionStatus getStatus();
    
    @Nonnull PublicKey getRemotePublicKey();
    
    @Nonnull String[] transformSending(@Nonnull Context context, @Nullable String msgText, @Nullable List<TLV> tlvs) throws OtrException;
    
    @Nonnull String handlePlainTextMessage(@Nonnull Context context, @Nonnull PlainTextMessage plainTextMessage) throws OtrException;

    @Nullable String handleDataMessage(@Nonnull Context context, @Nonnull DataMessage message) throws OtrException;

    void handleErrorMessage(@Nonnull Context context, @Nonnull ErrorMessage errorMessage) throws OtrException;
    
    void secure(@Nonnull Context context) throws OtrException;
    
    void end(@Nonnull Context context) throws OtrException;
    
    // FIXME How to respond for non-encrypted states where SmpTlvHandler is not available?
    @Nonnull SmpTlvHandler getSmpTlvHandler();
}
