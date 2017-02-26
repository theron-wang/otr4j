/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.SM;
import net.java.otr4j.crypto.SM.SMException;
import net.java.otr4j.crypto.SM.SMAbortedException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.TLV;

/**
 * SMP TLV Handler handles any interaction w.r.t. mutual authentication using
 * SMP (Socialist Millionaires Protocol).
 *
 * @author Danny van Heumen
 */
// TODO move SMP to separate package (including crypto.SM state implementations) and make states package-private.
public final class SmpTlvHandler {

    private static final byte[] VERSION_BYTE = new byte[]{1};

    private final SmpEngineHost engineHost;
    private final StateEncrypted session;
    private final SharedSecret s;
    private final Context sessionContext;
    private final SM sm;
    private final InstanceTag receiverInstanceTag;

    /**
     * Construct an OTR Socialist Millionaire handler object.
     *
     * @param session The session reference.
     * @param context Session context.
     * @param s The session's shared secret.
     */
    SmpTlvHandler(@Nonnull final StateEncrypted session, @Nonnull final Context context, @Nonnull final SharedSecret s) {
        this.session = Objects.requireNonNull(session);
        this.s = Objects.requireNonNull(s);
        this.engineHost = Objects.requireNonNull(context.getHost());
        this.sm = new SM(context.secureRandom());
        this.receiverInstanceTag = context.getReceiverInstanceTag();
        this.sessionContext = Objects.requireNonNull(context);
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
        final byte[] ourFp = engineHost.getLocalFingerprintRaw(session
                .getSessionID());
        final PublicKey remotePublicKey = session.getRemotePublicKey();
        final byte[] theirFp = OtrCryptoEngine.getFingerprintRaw(remotePublicKey);
        final byte[] sessionId = this.s.ssid();
        final byte[] secretBytes = secret.getBytes(SerializationUtils.UTF8);
        final byte[] combinedSecret;
        if (initiating) {
            combinedSecret = OtrCryptoEngine.sha256Hash(VERSION_BYTE, ourFp, theirFp, sessionId, secretBytes);
        } else {
            combinedSecret = OtrCryptoEngine.sha256Hash(VERSION_BYTE, theirFp, ourFp, sessionId, secretBytes);
        }

        byte[] smpmsg;
        if (initiating) {
            try {
                smpmsg = sm.step1(combinedSecret);
            }
            catch (final SM.SMAbortedException e) {
                // As prescribed by OTR, we must always be allowed to initiate a
                // new SMP exchange. In case another SMP exchange is in
                // progress, an abort is signaled. We honor the abort exception
                // and send the abort signal to the counter party. Then we
                // immediately initiate a new SMP exchange as requested.
                sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
                SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
                try {
                    smpmsg = sm.step1(combinedSecret);
                }
                catch (final SMException ex) {
                    throw new OtrException(ex);
                }
            }
            catch (SMException ex) {
                throw new OtrException(ex);
            }
        } else {
            try {
                smpmsg = sm.step2b(combinedSecret);
            }
            catch (final SMAbortedException ex) {
                sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
                SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
                throw new OtrException(ex);
            }
            catch (final SMException ex) {
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
        final TLV sendtlv = new TLV(TLV.SMP_ABORT, TLV.EMPTY);
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
        return OtrCryptoEngine.getFingerprint(session.getRemotePublicKey());
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
            SmpEngineHostUtil.askForSecret(engineHost, session.getSessionID(),
                    this.receiverInstanceTag, questionUTF);
        }
        catch (final SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (final SMException e) {
            SmpEngineHostUtil.smpError(engineHost, session.getSessionID(),
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
            SmpEngineHostUtil.askForSecret(engineHost, session.getSessionID(),
                    this.receiverInstanceTag, null);
        }
        catch (final SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (final SMException e) {
            SmpEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP2(@Nonnull final TLV tlv) throws OtrException {
        
        try {
            final byte[] nextmsg = sm.step3(tlv.getValue());
            /* Send msg with next smp msg content */
            final TLV sendtlv = new TLV(TLV.SMP3, nextmsg);
            final DataMessage m = session.transformSending(this.sessionContext,
                    "", Collections.singletonList(sendtlv));
            this.sessionContext.injectMessage(m);
        }
        catch (final SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (final SMException e) {
            SmpEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP3(@Nonnull final TLV tlv) throws OtrException {
        try {
            final byte[] nextmsg = sm.step4(tlv.getValue());
            /* Set trust level based on result */
            if (this.sm.status() == SM.Status.SUCCEEDED) {
                SmpEngineHostUtil.verify(engineHost, session.getSessionID(),
                        getFingerprint());
            } else {
                SmpEngineHostUtil.unverify(engineHost, session.getSessionID(),
                        getFingerprint());
            }
            /* Send msg with next smp msg content */
            final TLV sendtlv = new TLV(TLV.SMP4, nextmsg);
            sendTLV(sendtlv);
        }
        catch (final SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (final SMException e) {
            SmpEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP4(@Nonnull final TLV tlv) throws OtrException {
        try {
            sm.step5(tlv.getValue());
            if (this.sm.status() == SM.Status.SUCCEEDED) {
                SmpEngineHostUtil.verify(engineHost, session.getSessionID(),
                        getFingerprint());
            } else {
                SmpEngineHostUtil.unverify(engineHost, session.getSessionID(), getFingerprint());
            }
        }
        catch (final SMAbortedException e) {
            sendTLV(new TLV(TLV.SMP_ABORT, TLV.EMPTY));
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
        catch (final SMException e) {
            SmpEngineHostUtil.smpError(engineHost, session.getSessionID(),
                    tlv.getType(), this.sm.status() == SM.Status.CHEATED);
            throw new OtrException(e);
        }
    }

    public void processTlvSMP_ABORT(@Nonnull final TLV tlv) throws OtrException {
        if (this.sm.abort()) {
            SmpEngineHostUtil.smpAborted(engineHost, session.getSessionID());
        }
    }

    private void sendTLV(@Nonnull final TLV tlv) throws OtrException {
        final DataMessage m = session.transformSending(this.sessionContext,
                "", Collections.singletonList(tlv));
        this.sessionContext.injectMessage(m);
    }
}
