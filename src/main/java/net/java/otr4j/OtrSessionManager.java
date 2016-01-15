/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.ArrayList;
import java.util.Hashtable;
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
     */
    // TODO consider creating a map on construction and making it final. Map could be minimum-sized to avoid large overhead in memory usage.
    private Map<SessionID, Session> sessions;

    /**
     * List for keeping track of listeners.
     */
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<OtrEngineListener>(0);

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

        if (sessions == null) {
            // TODO Hashtable is obsolete collection. Should we use HashMap for this?
            sessions = new Hashtable<SessionID, Session>();
        }

        if (!sessions.containsKey(sessionID)) {
            final Session session = new Session(sessionID, this.host);
            sessions.put(sessionID, session);

            // TODO consider refactoring this to singleton instance of an OtrEngineListener that gets re-used for each new sessions. This should be feasible, as the listener only reads data and does not modify state.
            session.addOtrEngineListener(new OtrEngineListener() {

                @Override
                public void sessionStatusChanged(final SessionID sessionID) {
                    // FIXME consider copying 'listeners' to avoid incidental ConcurrentModificationExceptions while iterating over elements (thread-safety)
                    OtrEngineListenerUtil.sessionStatusChanged(listeners, sessionID);
                }

                @Override
                public void multipleInstancesDetected(final SessionID sessionID) {
                    // FIXME consider copying 'listeners' to avoid incidental ConcurrentModificationExceptions while iterating over elements (thread-safety)
                    OtrEngineListenerUtil.multipleInstancesDetected(listeners, sessionID);
                }

                @Override
                public void outgoingSessionChanged(final SessionID sessionID) {
                    // FIXME consider copying 'listeners' to avoid incidental ConcurrentModificationExceptions while iterating over elements (thread-safety)
                    OtrEngineListenerUtil.outgoingSessionChanged(listeners, sessionID);
                }
            });
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
