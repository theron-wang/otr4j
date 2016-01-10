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
import java.util.logging.Level;
import java.util.logging.Logger;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 * @author George Politis
 */
public class OtrSessionManager {

    private static final Logger LOGGER = Logger.getLogger(OtrSessionManager.class.getName());

    public OtrSessionManager(final OtrEngineHost host) {
        if (host == null) {
            throw new IllegalArgumentException("OtrEngineHost is required.");
        }

        this.host = host;
    }

    private final OtrEngineHost host;
    private Map<SessionID, Session> sessions;

    /**
     * Fetches the existing session with this {@link SessionID} or creates a new
     * {@link Session} if one does not exist.
     *
     * @param sessionID
     * @return MVN_PASS_JAVADOC_INSPECTION
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

            session.addOtrEngineListener(new OtrEngineListener() {

                @Override
                public void sessionStatusChanged(final SessionID sessionID) {
                    // TODO consider writing util for safely handing listeners
                    for (final OtrEngineListener l : listeners) {
                        try {
                            // Calling the listeners in order to inform of
                            // events. As a service to the user we log any
                            // problems that occur while calling listeners.
                            l.sessionStatusChanged(sessionID);
                        } catch (RuntimeException e) {
                            LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'sessionStatusChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
                        }
                    }
                }

                @Override
                public void multipleInstancesDetected(final SessionID sessionID) {
                    // TODO consider writing util for safely handing listeners
                    for (final OtrEngineListener l : listeners) {
                        try {
                            // Calling the listeners in order to inform of
                            // events. As a service to the user we log any
                            // problems that occur while calling listeners.
                            l.multipleInstancesDetected(sessionID);
                        } catch (RuntimeException e) {
                            LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'multipleInstancesDetected' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
                        }
                    }
                }

                @Override
                public void outgoingSessionChanged(final SessionID sessionID) {
                    // TODO consider writing util for safely handing listeners
                    for (final OtrEngineListener l : listeners) {
                        try {
                            // Calling the listeners in order to inform of
                            // events. As a service to the user we log any
                            // problems that occur while calling listeners.
                            l.outgoingSessionChanged(sessionID);
                        } catch (RuntimeException e) {
                            LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'outgoingSessionChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
                        }
                    }
                }
            });
            return session;
        } else {
            return sessions.get(sessionID);
        }
    }

    // TODO consider converting Vector to ArrayList (check synchronization)
    private final List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

    public void addOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    public void removeOtrEngineListener(final OtrEngineListener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }
}
