package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.SessionID;

/**
 * Utilities for OtrKeyManagerListener.
 *
 * @author Danny van Heumen
 */
class OtrKeyManagerListenerUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrKeyManagerListenerUtil.class.getCanonicalName());

    private OtrKeyManagerListenerUtil() {
        // This utility class need not be instantiated.
    }

    static void verificationStatusChanged(final Iterable<OtrKeyManagerListener> listeners, final SessionID sessionID) {
        for (final OtrKeyManagerListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.verificationStatusChanged(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'verificationStatusChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }
}
