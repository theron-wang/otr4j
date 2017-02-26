package net.java.otr4j.session.smp;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Abstract class implementing the base for SMP exchange states.
 *
 * This implementation is dedicated to the management of SMP exchange state
 * only. Specific exceptions are thrown to indicate the unexpected state
 * changes.
 */
abstract class AbstractSMPState {

    static final BigInteger G1 = SM.GENERATOR_S;

    private final SecureRandom sr;

    AbstractSMPState(@Nonnull final SecureRandom sr) {
        this.sr = Objects.requireNonNull(sr);
    }

    /**
     * Status of the SM protocol.
     *
     * @return Returns UNDECIDED in case SMP has not been executed, or is
     * executing but not yet completed. Returns SUCCEEDED in case SMP has
     * executed successfully. Returns FAILED in case SMP has executed
     * unsuccessfully.
     */
    @Nonnull
    abstract SMPStatus status();

    /**
     * Start SMP negotiation.
     *
     * An SMP exchange can be started at any time during the protocol state. For
     * any state but the first, we need to send an SMP abort message. After
     * having sent the SMP abort message it is perfectly valid to immediately
     * start a new SMP exchange.
     *
     * The default implementation resets the state and sends the
     * SMAbortedOperation exception. StateExpect1 should override and create the
     * initiation message.
     *
     * @param astate State of SM exchange (Alice)
     * @param secret SMP secret that is commonly known by both parties, to test counter party.
     */
    @Nonnull
    byte[] startSMP(@Nonnull final SM astate, @Nonnull final byte[] secret) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        astate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received start SMP request at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName()
                        + ") It is allowed to call startSMP() immediately after having sent the type 6 TLV signaling SMP abort in order to immediately start a new SMP exchange.");
    }

    /**
     * Abort SMP negotiation.
     *
     * The state is reset due to the abort operation. Calling code is expected
     * to send type 6 TLV to signal SMP abort.
     *
     * @param state The current state of SMP exchange.
     * @return Returns true if SMP was originally in progress, or false for SMP
     * that was already in the initial/final state.
     */
    boolean smpAbort(@Nonnull final SM state) {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        state.setState(new StateExpect1(this.sr));
        return inprogress;
    }

    /**
     * Step 2: Message sent by Alice to Bob. Begin a DH exchange to determine
     * generators g2, g3.
     *
     * @param bstate State of SM exchange (Bob)
     * @param input Input of initiation message.
     */
    void smpMessage1a(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        bstate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received SMP message 1 at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 2 (part 2): User has entered secret. Secret must now be passed on to
     * SM protocol for reply message to be constructed.
     *
     * @param bstate State of SM exchange (Bob)
     * @param secret Secret entered by user.
     * @return Returns reply to initiation message.
     */
    @Nonnull
    byte[] smpMessage1b(@Nonnull final SM bstate, @Nonnull final byte[] secret) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        bstate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received follow up to SMP message 1 at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 2: Message sent by Bob to Alice. Complete DH exchange. Determine new
     * generators g2, g3. Begin construction of values used in final comparison.
     *
     * @param astate State of SM exchange (Alice)
     * @param input Reply to initiation message.
     * @return Returns reply.
     */
    @Nonnull
    byte[] smpMessage2(@Nonnull final SM astate, @Nonnull final byte[] input) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        astate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received SMP message 2 at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 3: Message sent by Alice to Bob. Alice's final message in SMP
     * exchange.
     *
     * @param bstate State of SM exchange (Bob)
     * @param input Reply from Alice to Bob's response to initiation message.
     * @return Returns the final message of SMP exchange to Alice.
     */
    @Nonnull
    byte[] smpMessage3(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        bstate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received SMP message 3 at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 4: Message sent by Bob to Alice. Bob's final message in SMP
     * exchange.
     *
     * @param astate State of SM exchange (Alice)
     * @param input Final reply from Bob with last parameters of SMP exchange.
     */
    void smpMessage4(@Nonnull final SM astate, @Nonnull final byte[] input) throws SMException {
        final boolean inprogress = status() == SMPStatus.INPROGRESS;
        astate.setState(new StateExpect1(this.sr));
        throw new SMAbortedException(inprogress,
                "Received SMP message 4 at incorrect state of the protocol. ("
                        + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Accessor to SecureRandom instance.
     *
     * @return Returns secure random instance.
     */
    @Nonnull
    final SecureRandom secureRandom() {
        return this.sr;
    }

    /**
     * Generate a random exponent
     *
     * @return the generated random exponent.
     */
    @Nonnull
    final BigInteger randomExponent() {
        final byte[] sb = new byte[SM.MOD_LEN_BYTES];
        this.sr.nextBytes(sb);
        return new BigInteger(1, sb);
    }

    /**
     * Proof of knowledge of a discrete logarithm.
     *
     * @param x the secret information
     * @param version the prefix to use for the hashing function
     * @return c and d.
     * @throws SMException when c and d could not be calculated
     */
    @Nonnull
    final BigInteger[] proofKnowLog(@Nonnull final BigInteger x, final int version) throws SMException
    {
        final BigInteger r = randomExponent();
        BigInteger temp = G1.modPow(r, SM.MODULUS_S);
        final BigInteger c = SM.hash(version, temp, null);
        temp = x.multiply(c).mod(SM.ORDER_S);
        final BigInteger d = r.subtract(temp).mod(SM.ORDER_S);
        return new BigInteger[] {c, d};
    }

    /**
     * Verify a proof of knowledge of a discrete logarithm.  Checks that c = h(g^d x^c)
     *
     * @param c c from remote party
     * @param d d from remote party
     * @param x our secret information
     * @param version the prefix to use
     * @throws SMException when proof check fails
     */
    final void checkKnowLog(@Nonnull final BigInteger c, @Nonnull final BigInteger d,
                            @Nonnull final BigInteger x, final int version) throws SMException
    {
        final BigInteger gd = G1.modPow(d, SM.MODULUS_S);
        final BigInteger xc = x.modPow(c, SM.MODULUS_S);
        final BigInteger gdxc = gd.multiply(xc).mod(SM.MODULUS_S);
        final BigInteger hgdxc = SM.hash(version, gdxc, null);

        if (hgdxc.compareTo(c) != 0) {
            throw new SMException("Proof checking failed");
        }
    }

    /**
     * Proof of knowledge of coordinates with first components being equal
     */
    @Nonnull
    final BigInteger[] proofEqualCoords(@Nonnull final BigInteger g2,
                                        @Nonnull final BigInteger g3, @Nonnull final BigInteger secret_mpi,
                                        @Nonnull final BigInteger r, final int version) throws SMException
    {
        final BigInteger r1 = randomExponent();
        final BigInteger r2 = randomExponent();

        /* Compute the value of c, as c = h(g3^r1, g1^r1 g2^r2) */
        BigInteger temp1 = G1.modPow(r1, SM.MODULUS_S);
        BigInteger temp2 = g2.modPow(r2, SM.MODULUS_S);
        temp2 = temp1.multiply(temp2).mod(SM.MODULUS_S);
        temp1 = g3.modPow(r1, SM.MODULUS_S);
        final BigInteger c = SM.hash(version, temp1, temp2);

        /* Compute the d values, as d1 = r1 - r c, d2 = r2 - secret c */
        temp1 = r.multiply(c).mod(SM.ORDER_S);
        final BigInteger d1 = r1.subtract(temp1).mod(SM.ORDER_S);

        temp1 = secret_mpi.multiply(c).mod(SM.ORDER_S);
        final BigInteger d2 = r2.subtract(temp1).mod(SM.ORDER_S);

        return new BigInteger[] {c, d1, d2};
    }

    /**
     * Verify a proof of knowledge of coordinates with first components being equal
     */
    final void checkEqualCoords(@Nonnull final BigInteger c, @Nonnull final BigInteger d1,
                                @Nonnull final BigInteger d2, @Nonnull final BigInteger p,
                                @Nonnull final BigInteger q, @Nonnull final BigInteger g2,
                                @Nonnull final BigInteger g3, final int version) throws SMException
    {
        /* To verify, we test that hash(g3^d1 * p^c, g1^d1 * g2^d2 * q^c) = c
         * If indeed c = hash(g3^r1, g1^r1 g2^r2), d1 = r1 - r*c,
         * d2 = r2 - secret*c.  And if indeed p = g3^r, q = g1^r * g2^secret
         * Then we should have that:
         *   hash(g3^d1 * p^c, g1^d1 * g2^d2 * q^c)
         * = hash(g3^(r1 - r*c + r*c), g1^(r1 - r*c + q*c) *
         *      g2^(r2 - secret*c + secret*c))
         * = hash(g3^r1, g1^r1 g2^r2)
         * = c
         */
        BigInteger temp2 = g3.modPow(d1, SM.MODULUS_S);
        BigInteger temp3 = p.modPow(c, SM.MODULUS_S);
        final BigInteger temp1 = temp2.multiply(temp3).mod(SM.MODULUS_S);

        temp2 = G1.modPow(d1, SM.MODULUS_S);
        temp3 = g2.modPow(d2, SM.MODULUS_S);
        temp2 = temp2.multiply(temp3).mod(SM.MODULUS_S);
        temp3 = q.modPow(c, SM.MODULUS_S);
        temp2 = temp3.multiply(temp2).mod(SM.MODULUS_S);

        final BigInteger cprime = SM.hash(version, temp1, temp2);

        if (c.compareTo(cprime) != 0) {
            throw new SMException("Proof checking failed");
        }
    }

    /**
     * Proof of knowledge of logs with exponents being equal
     */
    @Nonnull
    final BigInteger[] proofEqualLogs(@Nonnull final BigInteger qab,
                                      @Nonnull final BigInteger x3, final int version) throws SMException
    {
        final BigInteger r = randomExponent();

        /* Compute the value of c, as c = h(g1^r, (Qa/Qb)^r) */
        BigInteger temp1 = G1.modPow(r, SM.MODULUS_S);
        BigInteger temp2 = qab.modPow(r, SM.MODULUS_S);
        final BigInteger c = SM.hash(version, temp1, temp2);

        /* Compute the d values, as d = r - x3 c */
        temp1 = x3.multiply(c).mod(SM.ORDER_S);
        final BigInteger d = r.subtract(temp1).mod(SM.ORDER_S);

        return new BigInteger[] {c, d};
    }

    /**
     * Verify a proof of knowledge of logs with exponents being equal
     */
    final void checkEqualLogs(@Nonnull final BigInteger c, @Nonnull final BigInteger d,
                              @Nonnull final BigInteger r, @Nonnull final BigInteger g3o,
                              @Nonnull final BigInteger qab, final int version) throws SMException
    {
        /* Here, we recall the exponents used to create g3.
         * If we have previously seen g3o = g1^x where x is unknown
         * during the DH exchange to produce g3, then we may proceed with:
         *
         * To verify, we test that hash(g1^d * g3o^c, qab^d * r^c) = c
         * If indeed c = hash(g1^r1, qab^r1), d = r1- x * c
         * And if indeed r = qab^x
         * Then we should have that:
         *   hash(g1^d * g3o^c, qab^d r^c)
         * = hash(g1^(r1 - x*c + x*c), qab^(r1 - x*c + x*c))
         * = hash(g1^r1, qab^r1)
         * = c
         */

        BigInteger temp2 = G1.modPow(d, SM.MODULUS_S);
        BigInteger temp3 = g3o.modPow(c, SM.MODULUS_S);
        final BigInteger temp1 = temp2.multiply(temp3).mod(SM.MODULUS_S);

        temp3 = qab.modPow(d, SM.MODULUS_S);
        temp2 = r.modPow(c, SM.MODULUS_S);
        temp2 = temp3.multiply(temp2).mod(SM.MODULUS_S);

        final BigInteger cprime = SM.hash(version, temp1, temp2);

        if (c.compareTo(cprime) != 0) {
            throw new SMException("Proof checking failed");
        }
    }

    /**
     * Check that an BigInteger is in the right range to be a (non-unit) group
     * element.
     *
     * @param g the BigInteger to check.
     * @throws SMException Throws SMException if check fails.
     */
    static void checkGroupElem(@Nonnull final BigInteger g) throws SMException
    {
        if(g.compareTo(BigInteger.valueOf(2)) < 0 ||
                g.compareTo(SM.MODULUS_MINUS_2) > 0) {
            throw new SMException("Invalid parameter");
        }
    }

    /**
     * Check that an BigInteger is in the right range to be a (non-zero)
     * exponent.
     *
     * @param x The BigInteger to check.
     * @throws SMException Throws SMException if check fails.
     */
    static void checkExpon(@Nonnull final BigInteger x) throws SMException
    {
        if (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(SM.ORDER_S) >= 0) {
            throw new SMException("Invalid parameter");
        }
    }
}
