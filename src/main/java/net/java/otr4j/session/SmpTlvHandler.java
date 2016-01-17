package net.java.otr4j.session;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SM;
import net.java.otr4j.crypto.SM.SMException;
import net.java.otr4j.crypto.SM.SMState;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationUtils;

public class SmpTlvHandler {

	private SMState smstate;
    private final OtrEngineHost engineHost;
	private final Session session;

	/**
	 * Construct an OTR Socialist Millionaire handler object.
	 * 
	 * @param session The session reference.
	 */
	public SmpTlvHandler(final Session session) {
		this.session = session;
		this.engineHost = session.getHost();
		reset();
	}

    /**
     * Reset SMState in order to provide clean, unused state.
     *
     * reset() is final to ensure expected behavior of resetting to clean state.
     */
	public final void reset() {
		smstate = new SMState();
	}

	/* Compute secret session ID as hash of agreed secret */
	private static byte[] computeSessionId(final BigInteger s) throws SMException {
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
	public List<TLV> initRespondSmp(final String question, final String secret, final boolean initiating) throws OtrException {
		if (!initiating && !smstate.asked) {
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

		byte[] bytes = secret.getBytes(SerializationUtils.UTF8);
		final int combined_buf_len = 41 + sessionId.length + bytes.length;
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
		System.arraycopy(bytes, 0,
				combined_buf, 41 + sessionId.length, bytes.length);

		final MessageDigest sha256;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException ex) {
			throw new OtrException(ex);
		}

		final byte[] combined_secret = sha256.digest(combined_buf);
		byte[] smpmsg;
		try {
			if (initiating) {
				smpmsg = SM.step1(smstate, combined_secret, this.session.secureRandom());
			} else {
				smpmsg = SM.step2b(smstate, combined_secret, this.session.secureRandom());
			}
		} catch (SMException ex) {
			throw new OtrException(ex);
		}

		// If we've got a question, attach it to the smpmsg
		if (question != null && initiating){
			bytes = question.getBytes(SerializationUtils.UTF8);
			final byte[] qsmpmsg = new byte[bytes.length + 1 + smpmsg.length];
			System.arraycopy(bytes, 0, qsmpmsg, 0, bytes.length);
			System.arraycopy(smpmsg, 0, qsmpmsg, bytes.length + 1, smpmsg.length);
			smpmsg = qsmpmsg;
		}

		final TLV sendtlv = new TLV(initiating?
				(question != null ? TLV.SMP1Q:TLV.SMP1) : TLV.SMP2, smpmsg);
		smstate.nextExpected = initiating? SM.EXPECT2 : SM.EXPECT3;
		smstate.approved = initiating || question == null;
        return makeTlvList(sendtlv);
	}

	/**
	 *  Create an abort TLV and reset our state.
	 *
	 *  @return TLVs to send to the peer
     *  @throws OtrException MVN_PASS_JAVADOC_INSPECTION
	 */
	public List<TLV> abortSmp() throws OtrException {
		final TLV sendtlv = new TLV(TLV.SMP_ABORT, new byte[0]);
		smstate.nextExpected = SM.EXPECT1;
        return makeTlvList(sendtlv);
	}

	public boolean isSmpInProgress() {
	    return smstate.nextExpected > SM.EXPECT1;
	}

	public String getFingerprint() {
		final PublicKey pubKey = session.getRemotePublicKey();
		try {
			return OtrCryptoEngine.getFingerprint(pubKey);
        } catch (OtrCryptoException e) {
            // TODO consider removing printStackTrace()
            e.printStackTrace();
        }
		return null;
	}

	public void processTlvSMP1Q(final TLV tlv) throws OtrException {
	    final int tlvType = tlv.getType();
	    if (smstate.nextExpected == SM.EXPECT1) {
			/* We can only do the verification half now.
			 * We must wait for the secret to be entered
			 * to continue. */
			final byte[] question = tlv.getValue();
			int qlen=0;
			for(; qlen!=question.length && question[qlen]!=0; qlen++){
			}
			if (qlen == question.length) {
                qlen=0;
            } else {
                qlen++;
            }
			final byte[] input = new byte[question.length-qlen];
			System.arraycopy(question, qlen, input, 0, question.length-qlen);
			try {
				SM.step2a(smstate, input, 1, this.session.secureRandom());
			} catch (SMException e) {
				throw new OtrException(e);
			}
			if (qlen != 0) {
                qlen--;
            }
			final byte[] plainq = new byte[qlen];
			System.arraycopy(question, 0, plainq, 0, qlen);
			if (smstate.smProgState != SM.PROG_CHEATED){
				smstate.asked = true;
				final String questionUTF = new String(plainq, SerializationUtils.UTF8);
                OtrEngineHostUtil.askForSecret(engineHost, session.getSessionID(), session.getReceiverInstanceTag(), questionUTF);
			} else {
                OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, true);
			    reset();
			}
		} else {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, false);
		}
	}

	public void processTlvSMP1(final TLV tlv) throws OtrException {
	    final int tlvType = tlv.getType();
	    if (smstate.nextExpected == SM.EXPECT1) {
			/* We can only do the verification half now.
			 * We must wait for the secret to be entered
			 * to continue. */
			try {
				SM.step2a(smstate, tlv.getValue(), 0, this.session.secureRandom());
			} catch (SMException e) {
				throw new OtrException(e);
			}
			if (smstate.smProgState!=SM.PROG_CHEATED) {
				smstate.asked = true;
                OtrEngineHostUtil.askForSecret(engineHost, session.getSessionID(), session.getReceiverInstanceTag(), null);
			} else {
                OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, true);
			    reset();
			}
		} else {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, false);
		}
    }

	public void processTlvSMP2(final TLV tlv) throws OtrException {
	    final int tlvType = tlv.getType();
	    if (smstate.nextExpected == SM.EXPECT2) {
			final byte[] nextmsg;
			try {
				nextmsg = SM.step3(smstate, tlv.getValue(), this.session.secureRandom());
			} catch (SMException e) {
				throw new OtrException(e);
			}
			if (smstate.smProgState != SM.PROG_CHEATED){
				/* Send msg with next smp msg content */
				final TLV sendtlv = new TLV(TLV.SMP3, nextmsg);
				smstate.nextExpected = SM.EXPECT4;
				final String[] msg = session.transformSending("", makeTlvList(sendtlv));
				for (String part : msg) {
					engineHost.injectMessage(session.getSessionID(), part);
				}
			} else {
                OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, true);
			    reset();
			}
		} else {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, false);
		}
    }

    public void processTlvSMP3(final TLV tlv) throws OtrException {
        final int tlvType = tlv.getType();
        if (smstate.nextExpected == SM.EXPECT3) {
			final byte[] nextmsg;
			try {
				nextmsg = SM.step4(smstate, tlv.getValue(), this.session.secureRandom());
			} catch (SMException e) {
				throw new OtrException(e);
			}

			/* Set trust level based on result */
			if (smstate.smProgState == SM.PROG_SUCCEEDED){
                OtrEngineHostUtil.verify(engineHost, session.getSessionID(), getFingerprint(), smstate.approved);
			} else {
                OtrEngineHostUtil.unverify(engineHost, session.getSessionID(), getFingerprint());
			}
			if (smstate.smProgState != SM.PROG_CHEATED){
				/* Send msg with next smp msg content */
				final TLV sendtlv = new TLV(TLV.SMP4, nextmsg);
				final String[] msg = session.transformSending("", makeTlvList(sendtlv));
				for (final String part : msg) {
					engineHost.injectMessage(session.getSessionID(), part);
				}
			} else {
                OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, true);
			}
            // The SMP session has completed (either successfully or otherwise).
            // We have an answer to the authentication session. Now, clean the
            // SMP state as there is no use for it anymore.
			reset();
		} else {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, false);
		}
    }

    public void processTlvSMP4(final TLV tlv) throws OtrException {
        final int tlvType = tlv.getType();
        if (smstate.nextExpected == SM.EXPECT4) {

			try {
				SM.step5(smstate, tlv.getValue());
			} catch (SMException e) {
				throw new OtrException(e);
			}
			if (smstate.smProgState == SM.PROG_SUCCEEDED){
                OtrEngineHostUtil.verify(engineHost, session.getSessionID(), getFingerprint(), smstate.approved);
			} else {
                OtrEngineHostUtil.unverify(engineHost, session.getSessionID(), getFingerprint());
			}
			if (smstate.smProgState != SM.PROG_CHEATED){
                // TODO if this is truly empty, why express it like this?
			} else {
                OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, true);
			}
            // The SMP session has completed (either successfully or otherwise).
            // We have an answer to the authentication session. Now, clean the
            // SMP state as there is no use for it anymore.
			reset();
		} else {
            OtrEngineHostUtil.smpError(engineHost, session.getSessionID(), tlvType, false);
		}
    }

    public void processTlvSMP_ABORT(final TLV tlv) throws OtrException {
        OtrEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        reset();
    }

    private List<TLV> makeTlvList(final TLV sendtlv) {
        // TODO replace with Collections.<TLV>singletonList?
        final List<TLV> tlvs = new ArrayList<TLV>(1);
        tlvs.add(sendtlv);
        return tlvs;
    }
}
