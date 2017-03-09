/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import javax.annotation.Nonnull;

import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.SessionID;

/**
 * This interface should be implemented by the host application. It notifies
 * about session status changes.
 *
 * @author George Politis
 */
public interface OtrEngineListener {

    /**
     * Event triggered in case of session status changes.
     *
     * @param sessionID The session ID.
     * @param receiver  The receiver instance for which the status has changed.
     *                  (It might not be the active outgoing session.) The
     *                  receiver instance tag may be {@link InstanceTag#ZERO_TAG}
     *                  in case an OTR v2 session was changed.
     */
    void sessionStatusChanged(@Nonnull SessionID sessionID, @Nonnull InstanceTag receiver);

    /**
     * Event triggered in case multiple instances are detected.
     *
     * @param sessionID The session ID
     */
    void multipleInstancesDetected(@Nonnull SessionID sessionID);

    /**
     * Event triggered in case the outgoing session has changed.
     *
     * @param sessionID The session ID
     */
    void outgoingSessionChanged(@Nonnull SessionID sessionID);
}
