/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.security.KeyPair;

import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.SessionID;

/**
 * This interface should be implemented by the host application. It is required
 * for otr4j to work properly. This provides the core interface between the app
 * and otr4j.
 *
 * TODO verify that OtrException throws are really expected for each of the methods. SMP methods 'smpError' and 'smpAborted' seem to interrupt a crucial step in the process: reset().
 *
 * @author George Politis
 */
public abstract interface OtrEngineHost {

    /**
     * Request host to inject a new message into the IM communication stream
     * upon which the OTR session is built.
     *
     * @param sessionID The session ID
     * @param msg The message to inject
     * @throws OtrException
     */
	public abstract void injectMessage(SessionID sessionID, String msg)
			throws OtrException;

    /**
     * Warn the user that an encrypted message was received that could not be
     * decrypted, most likely because it was encrypted to a different session,
     * or an old session.
     *
     * @param sessionID The session ID
     * @throws OtrException
     */
	public abstract void unreadableMessageReceived(SessionID sessionID)
			throws OtrException;

    /**
     * Display the message to the user, but warn him that the message was
     * received decrypted.
     *
     * @param sessionID The session ID
     * @param msg the body of the received message that was not encrypted
     * @throws OtrException
     */
	public abstract void unencryptedMessageReceived(SessionID sessionID,
			String msg) throws OtrException;

    /**
     * Ask Engine Host to show provided error message that was received over
     * OTR.
     *
     * @param sessionID the session ID
     * @param error the error message
     * @throws OtrException
     */
	public abstract void showError(SessionID sessionID, String error)
			throws OtrException;

    /**
     * Call Engine Host to inform of SMP error during authentication.
     *
     * @param sessionID the session ID
     * @param tlvType the TLV type
     * @param cheated status indicator for cheating (interruption before SMP
     * verification step was able to complete)
     * @throws OtrException OtrException
     */
	public abstract void smpError(SessionID sessionID, int tlvType,
			boolean cheated) throws OtrException;

    /**
     * Call Engine Host to inform of SMP abort.
     *
     * @param sessionID the session ID
     * @throws OtrException OtrException
     */
	public abstract void smpAborted(SessionID sessionID) throws OtrException;

    /**
     * Signal Engine Host that OTR secure session is finished.
     *
     * @param sessionID the session ID
     * @param msgText message text
     * @throws OtrException OtrException
     */
	public abstract void finishedSessionMessage(SessionID sessionID,
			String msgText) throws OtrException;

    /**
     * Signal Engine Host that current policy dictates that a secure session is
     * required for messages to be sent.
     *
     * @param sessionID the session ID
     * @param msgText the encryption required message
     * @throws OtrException OtrException
     */
	public abstract void requireEncryptedMessage(SessionID sessionID,
			String msgText) throws OtrException;

    /**
     * Request the current session policy for provided session ID.
     *
     * @param sessionID the session ID
     * @return Returns the current policy for specified session.
     */
	public abstract OtrPolicy getSessionPolicy(SessionID sessionID);

	/**
	 * Get instructions for the necessary fragmentation operations.
	 *
	 * If no fragmentation is necessary, return {@link Integer#MAX_VALUE} to
	 * indicate the largest possible fragment size. Return any positive
	 * integer to specify a maximum fragment size and enable fragmentation
	 * using that boundary condition. If specified max fragment size is too
	 * small to fit at least the fragmentation overhead + some part of the
	 * message, fragmentation will fail with an IOException when
	 * fragmentation is attempted during message encryption.
	 *
	 * @param sessionID
	 *            the session ID of the session
	 * @return Returns the maximum fragment size allowed. Or return the
	 * maximum value possible, {@link Integer#MAX_VALUE}, if fragmentation
	 * is not necessary.
	 */
	public abstract int getMaxFragmentSize(SessionID sessionID);

    /**
     * Request local key pair from Engine Host.
     *
     * @param sessionID the session ID
     * @return Returns the local key pair.
     * @throws OtrException OtrException
     */
	public abstract KeyPair getLocalKeyPair(SessionID sessionID)
			throws OtrException;

    /**
     * Request local fingerprint in raw byte form.
     *
     * @param sessionID the session ID
     * @return Returns the raw fingerprint bytes.
     */
	public abstract byte[] getLocalFingerprintRaw(SessionID sessionID);

    /**
     * Signal Engine Host to ask user for answer to the question provided by the
     * other party in the authentication session.
     *
     * @param sessionID the session ID
     * @param receiverTag the receiver instance tag
     * @param question the question to be asked to the user by the Engine Host
     */
	public abstract void askForSecret(SessionID sessionID, InstanceTag receiverTag, String question);

    /**
     * When a remote user's key is verified via the Socialist Millionaire's
     * Protocol (SMP) shared passphrase or question/answer, this method will be
     * called upon successful completion of that process.
     *
     * @param sessionID of the session where the SMP happened.
     * @param fingerprint of the key to verify
     * @param approved
     */
	public abstract void verify(SessionID sessionID, String fingerprint, boolean approved);

    /**
     * If the Socialist Millionaire's Protocol (SMP) process fails, then this
     * method will be called to make sure that the session is marked as
     * untrustworthy.
     *
     * @param sessionID of the session where the SMP happened.
     * @param fingerprint of the key to unverify
     */
	public abstract void unverify(SessionID sessionID, String fingerprint);

    /**
     * When a message is received that is unreadable for some reason, for
     * example the session keys are lost/deleted already, then the Engine Host
     * is asked to provide a suitable reply to send back as an OTR error
     * message.
     *
     * @param sessionID the session ID
     * @return Returns an error message.
     */
	public abstract String getReplyForUnreadableMessage(SessionID sessionID);

    /**
     * Return the localized message that explains to the recipient how to get an
     * OTR-enabled client. This is sent as part of the initial OTR Query message
     * that prompts the other side to set up an OTR session. If this returns
     * {@code null} or {@code ""}, then otr4j will use the built-in default
     * message specified in
     * {@link SerializationConstants#DEFAULT_FALLBACK_MESSAGE}
     *
     * @param sessionID
     * @return String the localized message
     */
	public abstract String getFallbackMessage(SessionID sessionID);

    /**
     * Signal the Engine Host that a message is received that is intended for
     * another instance. The (local) user may have multiple OTR capable chat
     * clients active on this account.
     *
     * @param sessionID the session ID
     */
	public abstract void messageFromAnotherInstanceReceived(SessionID sessionID);

    /**
     * Signal the Engine Host that we have received a message that is intended
     * for us, but is sent from another instance. Our chat buddy may be logged
     * in at multiple locations.
     *
     * @param sessionID the session ID
     */
	public abstract void multipleInstancesDetected(SessionID sessionID);
}
