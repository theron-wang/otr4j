package net.java.otr4j.session.smp;

import javax.annotation.Nonnull;
import java.math.BigInteger;

/**
 * SMP state in expectation of SMP message 3: Alice's final message in SMP
 * exchange.
 *
 * In this state we accept message 3 (TLV type 4).
 */
final class StateExpect3 extends AbstractSMPState {

    final BigInteger x3;
    final BigInteger g2;
    final BigInteger g3;
    final BigInteger g3o;
    final BigInteger p;
    final BigInteger q;

    StateExpect3(@Nonnull final StateExpect1 previous, @Nonnull final BigInteger p, @Nonnull final BigInteger q) {
        super(previous.secureRandom());
        this.x3 = previous.x3;
        this.g2 = previous.g2;
        this.g3 = previous.g3;
        this.g3o = previous.g3o;
        this.p = p;
        this.q = q;
    }

    @Override
    @Nonnull
    SMPStatus status() {
        return SMPStatus.INPROGRESS;
    }

    @Override
    @Nonnull
    byte[] smpMessage3(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SMException {
        /* Read from input to find the mpis */
        final BigInteger[] msg3 = SM.unserialize(input);

        final BigInteger[] msg4 = new BigInteger[3];

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg3[0]);
        checkGroupElem(msg3[1]);
        checkGroupElem(msg3[5]);
        checkExpon(msg3[3]);
        checkExpon(msg3[4]);
        checkExpon(msg3[7]);

        /* Verify Alice's coordinate equality proof */
        checkEqualCoords(msg3[2], msg3[3], msg3[4], msg3[0], msg3[1], g2, g3, 6);

        /* Find Pa/Pb and Qa/Qb */
        BigInteger inv = p.modInverse(SM.MODULUS_S);
        final BigInteger pab = msg3[0].multiply(inv).mod(SM.MODULUS_S);
        inv = q.modInverse(SM.MODULUS_S);
        final BigInteger qab = msg3[1].multiply(inv).mod(SM.MODULUS_S);


        /* Verify Alice's log equality proof */
        checkEqualLogs(msg3[6], msg3[7], msg3[5], g3o, qab, 7);

        /* Calculate Rb and proof */
        msg4[0] = qab.modPow(x3, SM.MODULUS_S);
        BigInteger[] res = proofEqualLogs(qab, x3, 8);
        msg4[1] = res[0];
        msg4[2] = res[1];

        final byte[] output = SM.serialize(msg4);

        /* Calculate Rab and verify that secrets match */

        final BigInteger rab = msg3[5].modPow(x3, SM.MODULUS_S);
        final int comp = rab.compareTo(pab);

        final SMPStatus status = (comp == 0) ? SMPStatus.SUCCEEDED : SMPStatus.FAILED;
        bstate.setState(new StateExpect1(this.secureRandom(), status));

        return output;
    }
}
