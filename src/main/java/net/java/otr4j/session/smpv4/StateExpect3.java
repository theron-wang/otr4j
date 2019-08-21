/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X06;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X07;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X08;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.crypto.ed448.Ed448.requireValidPoint;
import static net.java.otr4j.session.api.SMPStatus.FAILED;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;

final class StateExpect3 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect3.class.getName());

    private final SecureRandom random;

    private final Point pb;
    private final Point qb;
    private final Scalar b3;
    private final Point g3a;
    private final Point g2;
    private final Point g3;

    StateExpect3(final SecureRandom random, final Point pb, final Point qb, final Scalar b3, final Point g3a,
            final Point g2, final Point g3) {
        this.random = requireNonNull(random);
        this.pb = requireNonNull(pb);
        this.qb = requireNonNull(qb);
        this.b3 = requireNonNull(b3);
        this.g3a = requireNonNull(g3a);
        this.g2 = requireNonNull(g2);
        this.g3 = requireNonNull(g3);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return INPROGRESS;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(final SMPContext context, final String question, final Scalar secret)
            throws SMPAbortException {
        context.setState(new StateExpect1(this.random, UNDECIDED));
        throw new SMPAbortException("Not in initial state. Aborting running SMP negotiation.");
    }

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(final SMPContext context, final String question, final Scalar secret) {
        // Given that this is an action by the local user, we don't see this as a violation of the protocol. Therefore,
        // we don't abort.
        LOGGER.log(Level.WARNING, "Requested to respond with secret answer, but no request is pending. Ignoring request.");
        return null;
    }

    @Nonnull
    @Override
    public SMPMessage4 process(final SMPContext context, final SMPMessage message) throws SMPAbortException {
        requireNonNull(context);
        requireNonNull(message);
        if (!(message instanceof SMPMessage3)) {
            throw new SMPAbortException("Received unexpected SMP message in StateExpect3.");
        }
        final SMPMessage3 smp3 = (SMPMessage3) message;
        if (!containsPoint(smp3.pa) || !containsPoint(smp3.qa) || !containsPoint(smp3.ra)) {
            throw new SMPAbortException("Message failed verification.");
        }
        if (!smp3.cp.constantTimeEquals(hashToScalar(SMP_VALUE_0X06, this.g3.multiply(smp3.d5).add(smp3.pa.multiply(smp3.cp)).encode(),
                multiplyByBase(smp3.d5).add(g2.multiply(smp3.d6)).add(smp3.qa.multiply(smp3.cp)).encode()))) {
            throw new SMPAbortException("Message failed verification.");
        }
        if (!smp3.cr.constantTimeEquals(hashToScalar(SMP_VALUE_0X07, multiplyByBase(smp3.d7).add(g3a.multiply(smp3.cr)).encode(),
                smp3.qa.add(this.qb.negate()).multiply(smp3.d7).add(smp3.ra.multiply(smp3.cr)).encode()))) {
            throw new SMPAbortException("Message failed verification.");
        }
        // Verify if the zero-knowledge proof succeeds on our end.
        final Point rab = smp3.ra.multiply(this.b3);
        if (rab.constantTimeEquals(smp3.pa.add(this.pb.negate()))) {
            LOGGER.log(Level.FINE, "Successful SMP verification.");
            context.setState(new StateExpect1(this.random, SUCCEEDED));
        } else {
            LOGGER.log(Level.FINE, "Failed SMP verification.");
            context.setState(new StateExpect1(this.random, FAILED));
        }
        // Compose final message to other party.
        final Point rb = requireValidPoint(smp3.qa.add(this.qb.negate()).multiply(this.b3));
        final Scalar r7 = generateRandomValueInZq(this.random);
        final Scalar cr = hashToScalar(SMP_VALUE_0X08, multiplyByBase(r7).encode(),
                smp3.qa.add(this.qb.negate()).multiply(r7).encode());
        final Scalar d7 = r7.subtract(this.b3.multiply(cr)).mod(primeOrder());
        return new SMPMessage4(rb, cr, d7);
    }
}
