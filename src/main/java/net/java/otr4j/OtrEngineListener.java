package net.java.otr4j;

import javax.annotation.Nonnull;
import net.java.otr4j.session.SessionID;

/**
 * This interface should be implemented by the host application. It notifies
 * about session status changes.
 * 
 * @author George Politis
 * 
 */
public interface OtrEngineListener {
	void sessionStatusChanged(@Nonnull SessionID sessionID);

	void multipleInstancesDetected(@Nonnull SessionID sessionID);

	void outgoingSessionChanged(@Nonnull SessionID sessionID);
}
