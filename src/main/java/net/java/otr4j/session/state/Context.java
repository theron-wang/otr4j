package net.java.otr4j.session.state;

import java.security.SecureRandom;
import javax.annotation.Nonnull;
import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.session.AuthContext;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.OfferStatus;
import net.java.otr4j.session.OtrFragmenter;
import net.java.otr4j.session.SessionID;

public interface Context {
    
    @Nonnull OtrEngineHost getHost();
    
    int getProtocolVersion();
    
    void injectMessage(@Nonnull AbstractMessage msg) throws OtrException;
    
    @Nonnull SessionID getSessionID();

    @Nonnull OtrPolicy getSessionPolicy();
    
    void setState(@Nonnull State state);
    
    @Nonnull InstanceTag getSenderInstanceTag();
    
    @Nonnull InstanceTag getReceiverInstanceTag();
    
    @Nonnull SecureRandom secureRandom();
    
    @Nonnull OfferStatus getOfferStatus();
    
    void setOfferStatus(@Nonnull OfferStatus status);
    
    @Nonnull AuthContext getAuthContext();
    
    @Nonnull OtrFragmenter fragmenter();
}
