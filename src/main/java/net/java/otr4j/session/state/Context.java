/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.security.SecureRandom;
import javax.annotation.Nonnull;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.SessionID;

/**
 * Session state context.
 *
 * Context of the session as used by the session state implementations.
 *
 * @author Danny van Heumen
 */
public interface Context {

    @Nonnull
    OtrEngineHost getHost();

    int getProtocolVersion();

    void injectMessage(@Nonnull Message msg) throws OtrException;

    @Nonnull
    SessionID getSessionID();

    @Nonnull
    OtrPolicy getSessionPolicy();

    void setState(@Nonnull State state);

    @Nonnull
    InstanceTag getSenderInstanceTag();

    @Nonnull
    InstanceTag getReceiverInstanceTag();

    @Nonnull
    SecureRandom secureRandom();

    @Nonnull
    OfferStatus getOfferStatus();

    void setOfferStatusSent();

    void startSession() throws OtrException;
}
