package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.SessionID;

/**
 * Utils for OtrEngineHost.
 *
 * <p>Methods that do not have a safe-handling counterpart implemented:</p>
 * <ul>
 * <li><i>injectMessage</i>: the OTR protocol depends on messages being injected for the
 * continuation of the process. Silencing any exceptions on this method will
 * silently halt the process which is not desirable.</li>
 *
 * <li><i>getSessionPolicy</i>: the Session policy is required information for further
 * execution. Do not silence such exceptions as they are important for correct
 * operation of the protocol itself.</li>
 *
 * <li><i>getMaxFragmentSize</i>: the fragment size is required for correct
 * functioning of the fragmentation function.</li>
 *
 * <li><i>getLocalKeyPair</i>: acquiring the local key pair is required for
 * continuing execution. There is no use in silencing exceptions that signal
 * problematic error cases.</li>
 *
 * <li><i>getLocalFingerprintRaw</i>: acquiring the local fingerprint is
 * required for continuing execution. There is no use in silencing exceptiosn
 * that signal problematic error cases.</li>
 * </ul>
 *
 * @author Danny van Heumen
 */
// TODO implement support method for verify(...). Log exceptions as SEVERE but continue execution as the protocol state already progressed.
// TODO implement support method for unverify(...). Log exceptions as SEVERE but continue execution as the protocol state already progressed.
// TODO what to do with askForSecret(...)
// TODO implement support method for smpError(...). Needed to ensure that *reset* is called even if a runtime exception occurs.
// TODO implement support method for smpAborted(...). Needed to ensure that *reset* is called even if a runtime exception occurs.
// TODO implement support method for showError(...).
// TODO implement support method for finishedSessionMessage(...).
// TODO implement support method for requireEncryptedMessage(...).
// TODO implement support method for getReplyForUnreadableMessage(...).
public final class OtrEngineHostUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineHostUtil.class.getCanonicalName());

    private OtrEngineHostUtil() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Safely call 'messageFromAnotherInstanceReceived' event on provided
     * OtrEngineHost. Catch any runtime exception and log occurrence of the
     * exception and consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void messageFromAnotherInstanceReceived(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.messageFromAnotherInstanceReceived(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'messageFromAnotherInstanceReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'multipleInstancesDetected' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.multipleInstancesDetected(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'multipleInstancesDetected' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unencryptedMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @param message the received message
     * @throws net.java.otr4j.OtrException Throws OtrException in case of expected failure cases.
     */
    public static void unencryptedMessageReceived(final OtrEngineHost host, final SessionID sessionID, final String message) throws OtrException {
        try {
            host.unencryptedMessageReceived(sessionID, message);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unencryptedMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unreadableMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @throws OtrException Throws OtrException in case of expected failure cases.
     */
    public static void unreadableMessageReceived(final OtrEngineHost host, final SessionID sessionID) throws OtrException {
        try {
            host.unreadableMessageReceived(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unreadableMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'getFallbackMessage' in order to retrieve customized fallback
     * message in case a chat client does not support OTR. In case of a runtime
     * exception, null will be returned causing otr4j to use its default
     * fallback message.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @return Returns the engine host's customized fallback message or null if
     * request failed with a runtime exception.
     */
    public static String getFallbackMessage(final OtrEngineHost host, final SessionID sessionID) {
        try {
            return host.getFallbackMessage(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getFallbackMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return null;
    }
}
