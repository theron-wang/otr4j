package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.SessionID;

/**
 * Utility class for safely handling the processing of OtrEngineListener
 * listeners.
 */
public final class OtrEngineListenerUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineListenerUtil.class.getName());

    private OtrEngineListenerUtil() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Safely call sessionStatusChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void sessionStatusChanged(final Iterable<OtrEngineListener> listeners, final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.sessionStatusChanged(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'sessionStatusChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call multipleInstancesDetected on all listeners in provided
     * iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(final Iterable<OtrEngineListener> listeners, final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.multipleInstancesDetected(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'multipleInstancesDetected' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call outgoingSessionChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void outgoingSessionChanged(final Iterable<OtrEngineListener> listeners, final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.outgoingSessionChanged(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'outgoingSessionChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }
}
