/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
public class OtrSessionManager {

    public OtrSessionManager(final OtrEngineHost host) {
        if (host == null) {
            throw new IllegalArgumentException("OtrEngineHost is required.");
        }

        this.host = host;
    }

    /**
     * The OTR Engine Host instance.
     */
    private final OtrEngineHost host;

    /**
     * Map with known sessions.
     *
     * As the session map is needed as soon as we get/create our first session,
     * we might as well construct it immediately.
     */
    private final Map<SessionID, Session> sessions = Collections.synchronizedMap(new HashMap<SessionID, Session>());

    /**
     * List for keeping track of listeners.
     */
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<OtrEngineListener>(0);

    /**
     * Singleton instance of OtrEngineListener for listeners registered with
     * Session Manager.
     *
     * This listener instance will be registered as an OtrEngineListener with
     * all new sessions.
     */
    private final OtrEngineListener sessionManagerListener = new OtrEngineListener() {
        // Note that this implementation must be context-agnostic as it is now
        // being reused in all sessions.

        @Override
        public void sessionStatusChanged(final SessionID sessionID) {
            OtrEngineListenerUtil.sessionStatusChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }

        @Override
        public void multipleInstancesDetected(final SessionID sessionID) {
            OtrEngineListenerUtil.multipleInstancesDetected(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }

        @Override
        public void outgoingSessionChanged(final SessionID sessionID) {
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }
    };

    /**
     * Fetches the existing session with this {@link SessionID} or creates a new
     * {@link Session} if one does not exist.
     *
     * @param sessionID
     * @return Returns Session instance that corresponds to provided sessionID.
     */
    public Session getSession(final SessionID sessionID) {

        if (sessionID == null || sessionID.equals(SessionID.EMPTY)) {
            throw new IllegalArgumentException();
        }

        if (!sessions.containsKey(sessionID)) {
            // TODO no synchronization between containsKey and put of new session. Should we really synchronize this?
            final Session session = new Session(sessionID, this.host);
            sessions.put(sessionID, session);
            session.addOtrEngineListener(sessionManagerListener);
            return session;
        } else {
            return sessions.get(sessionID);
        }
    }

    /**
     * Add a new OtrEngineListener.
     *
     * @param l the listener
     */
    public void addOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    /**
     * Remove a registered OtrEngineListener.
     *
     * @param l the listener
     */
    public void removeOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }
}
