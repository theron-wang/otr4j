package net.java.otr4j.session.state;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SM;
import net.java.otr4j.crypto.SM.SMException;
import net.java.otr4j.crypto.SM.SMAbortedException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.TLV;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.StateEncrypted;

public class SmpTlvHandler {

    private final OtrEngineHost engineHost;
	private final StateEncrypted session;
    // FIXME I think we should not store this context, however it cannot hurt since we access this SMP handler through the same instance.
    private final Context sessionContext;
    private final SM sm;
    private final InstanceTag receiverInstanceTag;

    /**
     * Indicates whether this is an approved exchange.
     *
     * An approved exchange means that the exchange was set up in such a way
     * that the user can be sure of verification in a way that a user can be
     */
    // FIXME I'm not sure that there is any real value to this indicator. Both with and without question, there is a notion of a shared secret. Question only hints at which 'shared secret' is expected.
    private boolean approved = false;

    /**
	 * Construct an OTR Socialist Millionaire handler object.
	 * 
	 * @param session The session reference.
     * @param context Session context.
	 */
	public SmpTlvHandler(@Nonnull final StateEncrypted session, @Nonnull final Context context) {
		this.session = Objects.requireNonNull(session);
		this.engineHost = Objects.requireNonNull(context.getHost());
        this.sm = new SM(context.secureRandom());
        this.receiverInstanceTag = context.getReceiverInstanceTag();
        this.sessionContext = Objects.requireNonNull(context);
	}

	/* Compute secret session ID as hash of agreed secret */
	private static byte[] computeSessionId(@Nonnull final BigInteger s) throws SMException {
		final byte[] sdata;

        /* convert agreed secret to bytes */
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final OtrOutputStream oos = new OtrOutputStream(out);
		try {
			oos.write(0x00);
			oos.writeBigInt(s);
			sdata = out.toByteArray();
		} catch (IOException e1) {
			throw new SMException(e1);
		} finally {
            try {
                oos.close();
            } catch (IOException ex) {
                throw new SMException(ex);
            }
        }

		/* Calculate the session id */
		final MessageDigest sha256;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new SMException("cannot find SHA-256");
		}
		final byte[] res = sha256.digest(sdata);
		final byte[] secure_session_id = new byte[8];
		System.arraycopy(res, 0, secure_session_id, 0, 8);
		return secure_session_id;
	}

	/**
	 *  Respond to or initiate an SMP negotiation
	 *
	 *  @param question
	 *  	The question to present to the peer, if initiating.
	 *  	May be <code>null</code> for no question.
	 *      If not initiating, then it should be received question
	 *      in order to clarify whether this is shared secret verification.
	 *  @param secret The secret.
	 *  @param initiating Whether we are initiating or responding to an initial request.
	 *
	 *  @return TLVs to send to the peer
     *  @throws OtrException MVN_PASS_JAVADOC_INSPECTION
	 */
	public List<TLV> initRespondSmp(@Nullable final String question, @Nonnull final String secret,
            final boolean initiating) throws OtrException {
        if (!initiating && this.sm.status() != SM.Status.INPROGRESS) {
            throw new OtrException(new IllegalStateException(
                    "There is no question to be answered."));
        }

		/*
		 * Construct the combined secret as a SHA256 hash of:
		 * Version byte (0x01), Initiator fingerprint (20 bytes),
		 * responder fingerprint (20 bytes), secure session id, input secret
		 */
		final byte[] our_fp = engineHost.getLocalFingerprintRaw(session
				.getSessionID());
		final byte[] their_fp;
		final PublicKey remotePublicKey = session.getRemotePublicKey();
		try {
			their_fp = OtrCryptoEngine.getFingerprintRaw(remotePublicKey);
		} catch (OtrCryptoException e) {
			throw new OtrException(e);
		}

		final byte[] sessionId;
		try {
			sessionId = computeSessionId(session.getS());
		} catch (SMException ex) {
			throw new OtrException(ex);
		}

		final byte[] secretBytes = secret.getBytes(SerializationUtils.UTF8);
		final int combined_buf_len = 41 + sessionId.length + secretBytes.length;
		final byte[] combined_buf = new byte[combined_buf_len];
		combined_buf[0]=1;
		if (initiating){
			System.arraycopy(our_fp, 0, combined_buf, 1, 20);
			System.arraycopy(their_fp, 0, combined_buf, 21, 20);
		} else {
			System.arraycopy(their_fp, 0, combined_buf, 1, 20);
			System.arraycopy(our_fp, 0, combined_buf, 21, 20);
		}
		System.arraycopy(sessionId, 0, combined_buf, 41, sessionId.length);
		System.arraycopy(secretBytes, 0,
				combined_buf, 41 + sessionId.length, secretBytes.length);

		final MessageDigest sha256;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException ex) {
			throw new OtrException(ex);
		}

		final byte[] combined_secret = sha256.digest(combined_buf);
		byte[] smpmsg;
        if (initiating) {
            try {
                smpmsg = sm.step1(combined_secret);
            }
            catch (SM.SMAbortedException e) {
                // As prescribed by OTR, we must always be allowed to initiate a
                // new SMP exchange. In case another SMP exchange is in
                // progress, an abort is signaled. We honor the abort exception
                // and send the abort signal to the counter party. Then we
                // immediately initiate a new SMP exchange as requested.
                sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
                OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
                try {
                    smpmsg = sm.step1(combined_secret);
                }
                catch (SMException ex) {
                    throw new OtrException(ex);
                }
            }
            catch (SMException ex) {
                throw new OtrException(ex);
            }
        } else {
            try {
                smpmsg = sm.step2b(combined_secret);
            }
            catch (SMAbortedException ex) {
                sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
                OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
                throw new OtrException(ex);
            }
            catch (SMException ex) {
                throw new OtrException(ex);
            }
        }

		// If we've got a question, attach it to the smpmsg
		if (question != null && initiating){
			final byte[] questionBytes = question.getBytes(SerializationUtils.UTF8);
			final byte[] qsmpmsg = new byte[questionBytes.length + 1 + smpmsg.length];
			System.arraycopy(questionBytes, 0, qsmpmsg, 0, questionBytes.length);
			System.arraycopy(smpmsg, 0, qsmpmsg, questionBytes.length + 1, smpmsg.length);
			smpmsg = qsmpmsg;
		}

		final TLV sendtlv = new TLV(initiating?
				(question != null ? TLV.SMP1Q:TLV.SMP1) : TLV.SMP2, smpmsg);
		approved = initiating || question == null;
        return Collections.singletonList(sendtlv);
	}

	/**
	 *  Create an abort TLV and reset our state.
	 *
	 *  @return TLVs to send to the peer
     *  @throws OtrException MVN_PASS_JAVADOC_INSPECTION
	 */
	public List<TLV> abortSmp() throws OtrException {
        this.sm.abort();
		final TLV sendtlv = new TLV(TLV.SMP_ABORT, new byte[0]);
        return Collections.singletonList(sendtlv);
	}

    /**
     * Reset SMP state to SMP_EXPECT1, the initial state, without sending an
     * abort message to the counterpart.
     */
    public void reset() {
        this.sm.abort();
    }

	public boolean isSmpInProgress() {
	    return this.sm.status() == SM.Status.INPROGRESS;
	}

	public String getFingerprint() {
		final PublicKey pubKey = session.getRemotePublicKey();
		try {
			return OtrCryptoEngine.getFingerprint(pubKey);
        } catch (OtrCryptoException e) {
            Logger.getLogger(SmpTlvHandler.class.getCanonicalName()).log(Level.WARNING, "Failed to get fingerprint.", e);
        }
        // This should not happen at all, so accept logging the exception as an indication that something is wrong.
		return null;
	}

    public void processTlvSMP1Q(@Nonnull final TLV tlv) throws OtrException {
        // We can only do the verification half now.
        // We must wait for the secret to be entered
		// to continue.
        final byte[] question = tlv.getValue();
        int qlen = 0;
        for (; qlen != question.length && question[qlen] != 0; qlen++) {
        }
        if (qlen == question.length) {
            qlen = 0;
        } else {
            qlen++;
        }
        final byte[] input = new byte[question.length - qlen];
        System.arraycopy(question, qlen, input, 0, question.length - qlen);
        try {
            sm.step2a(input);
            if (qlen != 0) {
                qlen--;
            }
            final byte[] plainq = new byte[qlen];
            System.arraycopy(question, 0, plainq, 0, qlen);
            final String questionUTF = new String(plainq, SerializationUtils.UTF8);
            OtrEngineHostUtil.askForSecret(engineHost, session.getSessionID(),
                    this.receiverInstanceTag, questionUTF);
        }
        catch (SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (SMException e) {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

	public void processTlvSMP1(@Nonnull final TLV tlv) throws OtrException {
        /* We can only do the verification half now.
			 * We must wait for the secret to be entered
			 * to continue. */
        try {
            sm.step2a(tlv.getValue());
            OtrEngineHostUtil.askForSecret(engineHost, session.getSessionID(),
                    this.receiverInstanceTag, null);
        }
        catch (SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (SMException e) {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

	public void processTlvSMP2(@Nonnull final TLV tlv) throws OtrException {
        
        try {
            final byte[] nextmsg = sm.step3(tlv.getValue());
            /* Send msg with next smp msg content */
            final TLV sendtlv = new TLV(TLV.SMP3, nextmsg);
            final String[] msg = session.transformSending(this.sessionContext,
                    "", Collections.singletonList(sendtlv));
            for (String part : msg) {
                engineHost.injectMessage(session.getSessionID(), part);
            }
        }
        catch (SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (SMException e) {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP3(@Nonnull final TLV tlv) throws OtrException {
        try {
            final byte[] nextmsg = sm.step4(tlv.getValue());
            /* Set trust level based on result */
            if (this.sm.status() == SM.Status.SUCCEEDED) {
                OtrEngineHostUtil.verify(engineHost, session.getSessionID(),
                        getFingerprint(), approved);
            } else {
                OtrEngineHostUtil.unverify(engineHost, session.getSessionID(),
                        getFingerprint());
            }
            /* Send msg with next smp msg content */
            final TLV sendtlv = new TLV(TLV.SMP4, nextmsg);
            sendTLV(sendtlv);
        }
        catch (SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (SMException e) {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP4(@Nonnull final TLV tlv) throws OtrException {
        try {
            sm.step5(tlv.getValue());
            if (this.sm.status() == SM.Status.SUCCEEDED) {
                OtrEngineHostUtil.verify(engineHost, session.getSessionID(),
                        getFingerprint(), approved);
            } else {
                OtrEngineHostUtil.unverify(engineHost, session.getSessionID(), getFingerprint());
            }
        }
        catch (SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, new byte[0]));
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (SMException e) {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP_ABORT(@Nonnull final TLV tlv) throws OtrException {
        if (this.sm.abort()) {
            OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
    }

    private void sendTLV(@Nonnull final TLV tlv) throws OtrException {
        final String[] msg = session.transformSending(this.sessionContext,
                "", Collections.singletonList(tlv));
        for (final String part : msg) {
            engineHost.injectMessage(session.getSessionID(), part);
        }
    }
}
