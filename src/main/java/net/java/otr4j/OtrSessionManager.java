/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 * @author George Politis
 */
public class OtrSessionManager {

    public OtrSessionManager(final OtrEngineHost host) {
        if (host == null)
            throw new IllegalArgumentException("OtrEngineHost is required.");

        this.setHost(host);
    }

    private OtrEngineHost host;
    private Map<SessionID, Session> sessions;

    /**
     * Fetches the existing session with this {@link SessionID} or creates a new
     * {@link Session} if one does not exist.
     *
     * @param sessionID
     * @return MVN_PASS_JAVADOC_INSPECTION
     */
    public Session getSession(final SessionID sessionID) {

        if (sessionID == null || sessionID.equals(SessionID.Empty))
            throw new IllegalArgumentException();

        if (sessions == null)
            sessions = new Hashtable<SessionID, Session>();

        if (!sessions.containsKey(sessionID)) {
            final Session session = new Session(sessionID, getHost());
            sessions.put(sessionID, session);

            session.addOtrEngineListener(new OtrEngineListener() {

                public void sessionStatusChanged(final SessionID sessionID) {
                    for (final OtrEngineListener l : listeners)
                        // TODO consider try-catching RTEs to avoid exception from listener to interfere with process
                        l.sessionStatusChanged(sessionID);
                }

                public void multipleInstancesDetected(final SessionID sessionID) {
                    for (final OtrEngineListener l : listeners)
                        // TODO consider try-catching RTEs to avoid exception from listener to interfere with process
                        l.multipleInstancesDetected(sessionID);
                }

                public void outgoingSessionChanged(final SessionID sessionID) {
                    for (final OtrEngineListener l : listeners)
                        // TODO consider try-catching RTEs to avoid exception from listener to interfere with process
                        l.outgoingSessionChanged(sessionID);
                }
            });
            return session;
        } else {
            return sessions.get(sessionID);
        }
    }

    private void setHost(final OtrEngineHost host) {
        this.host = host;
    }

    private OtrEngineHost getHost() {
        return host;
    }

    private final List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

    public void addOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l))
                listeners.add(l);
        }
    }

    public void removeOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }
}
