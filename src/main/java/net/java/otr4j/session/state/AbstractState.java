/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import javax.annotation.Nonnull;
import net.java.otr4j.api.OtrEngineHostUtil;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.io.messages.ErrorMessage;

/**
 * Abstract base implementation for session state implementations.
 *
 * @author Danny van Heumen
 */
abstract class AbstractState implements State {

    static final String DEFAULT_REPLY_UNREADABLE_MESSAGE = "This message cannot be read.";

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        OtrEngineHostUtil.showError(context.getHost(), this.getSessionID(), errorMessage.error);
    }
}
