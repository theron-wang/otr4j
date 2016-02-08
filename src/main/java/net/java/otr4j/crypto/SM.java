/*
 *  Java OTR library
 *  Copyright (C) 2008-2009  Ian Goldberg, Muhaimeen Ashraf, Andrew Chung,
 *                           Can Tang
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Ported to otr4j by devrandom */

package net.java.otr4j.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;


import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationUtils;


public final class SM {
    
    /**
     * Safe maximum array size. Copied from OpenJDK 7 implementation.
     * (http://hg.openjdk.java.net/jdk7/jdk7/jdk/file/tip/src/share/classes/java/util/ArrayList.java#l190)
     * A few bytes are reserved for overhead. This value seems to be quite
     * universally accepted safe maximum.
     */
    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;
    
    private State state;

    public SM(@Nonnull final SecureRandom sr) {
        if (sr == null) {
            throw new NullPointerException("sr");
        }
        this.state = new StateExpect1(sr);
    }

    void setState(@Nonnull final State state) {
        this.state = state;
    }

    static public class SMState{
        // TODO update code to get rid of obsolete SMState.
        
        BigInteger secret, x2, x3, g1, g2, g3, g3o, p, q, pab, qab;
        public int nextExpected;
        public int smProgState;
		public boolean approved;
		public boolean asked;
        
        /**
         * Ctor.
         */
        public SMState(){
            // we could remove g1 in favor of using G1 (constant) directly
            g1 = GENERATOR_S;
            smProgState = SM.PROG_OK;
            approved = false;
            asked = false;
        }
    }

	static public class SMException extends Exception {
		private static final long serialVersionUID = 1L;

		public SMException() {
			super("");
		}

		public SMException(final Throwable cause) {
			super(cause);
		}

		public SMException(final String message) {
			super(message);
		}

        public SMException(final String message, final Throwable cause) {
            super(message, cause);
        }
	}

    /**
     * SM Aborted exception indicates that the current SMP exchange is aborted
     * and the state reset to default.
     */
    static class SMAbortedException extends SMException {

        private static final long serialVersionUID = 8062094133300893010L;

        public SMAbortedException(@Nonnull final String message) {
            super(message);
        }
    }

	public static final int EXPECT1 = 0;
	public static final int EXPECT2 = 1;
	public static final int EXPECT3 = 2;
	public static final int EXPECT4 = 3;
	public static final int EXPECT5 = 4;
	
	public static final int PROG_OK = 0;
	public static final int PROG_CHEATED = -2;
	public static final int PROG_FAILED = -1;
	public static final int PROG_SUCCEEDED = 1;

	public static final int MSG1_LEN = 6;
	public static final int MSG2_LEN = 11;
	public static final int MSG3_LEN = 8;
	public static final int MSG4_LEN = 3;
	
	public static final BigInteger MODULUS_S = new BigInteger(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);
	
	public static final BigInteger MODULUS_MINUS_2 = new BigInteger(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD", 16);
	
	public static final BigInteger ORDER_S = new BigInteger(
			"7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68"+
		    "948127044533E63A0105DF531D89CD9128A5043CC71A026E"+
		    "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122"+
		    "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6"+
		    "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E"+
		    "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF"+
		    "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36"+
		    "B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF", 16);
	
	public static final BigInteger GENERATOR_S = BigInteger.valueOf(2l);
	public static final int MOD_LEN_BITS = 1536;
	public static final int MOD_LEN_BYTES = 192;
	
	/**
	 * Hash one or two BigIntegers. To hash only one BigInteger, b may be set to
     * NULL.
     *
     * @param version the prefix to use
     * @param a The 1st BigInteger to hash.
     * @param b The 2nd BigInteger to hash.
     * @return the BigInteger for the resulting hash value.
     * @throws net.java.otr4j.crypto.SM.SMException when the SHA-256 algorithm
     * is missing or when the biginteger can't be serialized.
	 */
	static BigInteger hash(final int version, @Nonnull final BigInteger a,
            @Nullable final BigInteger b) throws SMException
	{
		try {
			final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			sha256.update((byte)version);
			sha256.update(SerializationUtils.writeMpi(a));
			if (b != null) {
                sha256.update(SerializationUtils.writeMpi(b));
            }
			return new BigInteger(1, sha256.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new SMException("cannot find SHA-256");
		} catch (IOException e) {
			throw new SMException("cannot serialize bigint");
		}
	}
	
	static byte[] serialize(@Nonnull final BigInteger[] ints) throws SMException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final OtrOutputStream oos = new OtrOutputStream(out);
		try {
			oos.writeInt(ints.length);
			for (final BigInteger i : ints) {
				oos.writeBigInt(i);
			}
			return out.toByteArray();
		} catch (IOException ex) {
			throw new SMException("cannot serialize bigints");
		} finally {
            try {
                oos.close();
            } catch (IOException ex) {
                throw new SMException(ex);
            }
        }
	}
	
	static BigInteger[] unserialize(@Nonnull final byte[] bytes) throws SMException {
        final ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        final OtrInputStream ois = new OtrInputStream(in);
		try {
			final int len = ois.readInt();
            if (len < 0) {
                // Length is read into (signed) int. Bit shifting is used to
                // compose the final int value, but bit shifting does not
                // prevent Java from interpreting the value as a signed int,
                // thus negative for values where sign bit is set.
                throw new SMException("Invalid number of ints: " + len);
            }
            // FIXME Do we want to limit this to a smaller number? Which number?
			if (len > MAX_ARRAY_SIZE) {
                // The maximum supported length by otr4j. Because of the reason
                // described above, the maximum supported value is only 2**31
                // big (minus some overhead).
				throw new SMException("Too many ints");
			}
			final BigInteger[] ints = new BigInteger[len];
			for (int i = 0 ; i < len ; i++) {
				ints[i] = ois.readBigInt();
			}
			return ints;
		} catch (IOException ex) {
			throw new SMException("cannot unserialize bigints");
		} finally {
            try {
                ois.close();
            } catch (IOException e) {
                throw new SMException("failed to close OtrInputStream", e);
            }
        }
	}

    @Nonnull
    public SMStatus status() {
        return this.state.status();
    }

	/** Create first message in SMP exchange.  Input is Alice's secret value
	 * which this protocol aims to compare to Bob's. The return value is a serialized
	 * BigInteger array whose elements correspond to the following:
	 * [0] = g2a, Alice's half of DH exchange to determine g2
	 * [1] = c2, [2] = d2, Alice's ZK proof of knowledge of g2a exponent
	 * [3] = g3a, Alice's half of DH exchange to determine g3
	 * [4] = c3, [5] = d3, Alice's ZK proof of knowledge of g3a exponent
     * @param secret MVN_PASS_JAVADOC_INSPECTION
     * @return MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public byte[] step1(@Nonnull final byte[] secret) throws SMException
	{
        return this.state.startSMP(this, secret);
	}
	
	/** Receive the first message in SMP exchange, which was generated by
	 *  step1.  Input is saved until the user inputs their secret
	 * information.  No output. 
     * @param input MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public void step2a(@Nonnull final byte[] input) throws SMException
	{
        this.state.smpMessage1a(this, input);
	}
	
	/** Create second message in SMP exchange.  Input is Bob's secret value.
	 * Information from earlier steps in the exchange is taken from Bob's
	 * state.  Output is a serialized mpi array whose elements correspond
	 * to the following:
	 * [0] = g2b, Bob's half of DH exchange to determine g2
	 * [1] = c2, [2] = d2, Bob's ZK proof of knowledge of g2b exponent
	 * [3] = g3b, Bob's half of DH exchange to determine g3
	 * [4] = c3, [5] = d3, Bob's ZK proof of knowledge of g3b exponent
	 * [6] = pb, [7] = qb, Bob's halves of the (Pa/Pb) and (Qa/Qb) values
	 * [8] = cp, [9] = d5, [10] = d6, Bob's ZK proof that pb, qb formed correctly 
     * @param secret MVN_PASS_JAVADOC_INSPECTION
     * @return MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public byte[] step2b(@Nonnull final byte[] secret) throws SMException
	{
	    return this.state.smpMessage1b(this, secret);
	}

	/** Create third message in SMP exchange.  Input is a message generated
	 * by otrl_sm_step2b. Output is a serialized mpi array whose elements
	 * correspond to the following:
	 * [0] = pa, [1] = qa, Alice's halves of the (Pa/Pb) and (Qa/Qb) values
	 * [2] = cp, [3] = d5, [4] = d6, Alice's ZK proof that pa, qa formed correctly
	 * [5] = ra, calculated as (Qa/Qb)^x3 where x3 is the exponent used in g3a
	 * [6] = cr, [7] = d7, Alice's ZK proof that ra is formed correctly 
     * @param input MVN_PASS_JAVADOC_INSPECTION
     * @return MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public byte[] step3(@Nonnull final byte[] input) throws SMException
	{
        return this.state.smpMessage2(this, input);
	}

	/** Create final message in SMP exchange.  Input is a message generated
	 * by otrl_sm_step3. Output is a serialized mpi array whose elements
	 * correspond to the following:
	 * [0] = rb, calculated as (Qa/Qb)^x3 where x3 is the exponent used in g3b
	 * [1] = cr, [2] = d7, Bob's ZK proof that rb is formed correctly
	 * This method also checks if Alice and Bob's secrets were the same.  If
	 * so, it returns NO_ERROR.  If the secrets differ, an INV_VALUE error is
	 * returned instead. 
     *
     * @param input MVN_PASS_JAVADOC_INSPECTION
     * @return MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public byte[] step4(@Nonnull final byte[] input) throws SMException
	{
        return this.state.smpMessage3(this, input);
	}

	/** Receives the final SMP message, which was generated in otrl_sm_step.
	 * This method checks if Alice and Bob's secrets were the same.  If
	 * so, it returns NO_ERROR.  If the secrets differ, an INV_VALUE error is
	 * returned instead. 
     * @param input MVN_PASS_JAVADOC_INSPECTION
	 * @throws SMException MVN_PASS_JAVADOC_INSPECTION
     */
	public void step5(@Nonnull final byte[] input) throws SMException
	{
        this.state.smpMessage4(this, input);
	}
}

/**
 * Abstract class implementing the base for SMP exchange states.
 *
 * This implementation is dedicated to the management of SMP exchange state
 * only. Specific exceptions are thrown to indicate the unexpected state
 * changes.
 */
abstract class State {
    // FIXME where do we do TLV sending? I suspect that this is best handled outside of TLV.
    // FIXME SMP state should only be preserved in MSGSTATE_ENCRYPTED.
    // FIXME any unexpected message should result in an smpError
    // FIXME consider implementing "processing" flag which cannot be unset, such that interruption of handling is considered cheating.

    static final BigInteger G1 = SM.GENERATOR_S;

    private final SecureRandom sr;

    State(@Nonnull final SecureRandom sr) {
        if (sr == null) {
            throw new NullPointerException("sr");
        }
        this.sr = sr;
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
    abstract SMStatus status();

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
     * @param secret
     * @throws net.java.otr4j.crypto.SM.SMStateException
     */
    byte[] startSMP(@Nonnull final SM astate, @Nonnull final byte[] secret) throws SM.SMAbortedException, SM.SMException {
        astate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received start SMP request at incorrect state of the protocol. ("
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
     */
    void smpAbort(@Nonnull final SM state) {
        state.setState(new StateExpect1(this.sr));
    }

    /**
     * Step 2: Message sent by Alice to Bob. Begin a DH exchange to determine
     * generators g2, g3.
     *
     * @param bstate State of SM exchange (Bob)
     * @param input Input of initiation message.
     */
    void smpMessage1a(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
        bstate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received SMP message 1 at incorrect state of the protocol. (" + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 2 (part 2): User has entered secret. Secret must now be passed on to
     * SM protocol for reply message to be constructed.
     *
     * @param bstate State of SM exchange (Bob)
     * @param secret Secret entered by user.
     * @return Returns reply to initiation message.
     */
    byte[] smpMessage1b(@Nonnull final SM bstate, @Nonnull final byte[] secret) throws SM.SMAbortedException, SM.SMException {
        bstate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received follow up to SMP message 1 at incorrect state of the protocol. (" + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 2: Message sent by Bob to Alice. Complete DH exchange. Determine new
     * generators g2, g3. Begin construction of values used in final comparison.
     *
     * @param astate State of SM exchange (Alice)
     * @param input Reply to initiation message.
     * @return Returns reply.
     */
    byte[] smpMessage2(@Nonnull final SM astate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
        astate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received SMP message 2 at incorrect state of the protocol. (" + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 3: Message sent by Alice to Bob. Alice's final message in SMP
     * exchange.
     *
     * @param bstate State of SM exchange (Bob)
     * @param input Reply from Alice to Bob's response to initiation message.
     * @return Returns the final message of SMP exchange to Alice.
     */
    byte[] smpMessage3(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
        bstate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received SMP message 3 at incorrect state of the protocol. (" + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Step 4: Message sent by Bob to Alice. Bob's final message in SMP
     * exchange.
     *
     * @param astate State of SM exchange (Alice)
     * @param input Final reply from Bob with last parameters of SMP exchange.
     */
    void smpMessage4(@Nonnull final SM astate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
        astate.setState(new StateExpect1(this.sr));
        throw new SM.SMAbortedException("Received SMP message 4 at incorrect state of the protocol. (" + this.getClass().getCanonicalName() + ")");
    }

    /**
     * Abort: In all cases, reset SMP state upon receiving SMP Abort message.
     *
     * @param state State of SM exchange
     */
    void smpMessageAbort(@Nonnull final SM state) {
        state.setState(new StateExpect1(this.sr));
    }

    /**
     * Accessor to SecureRandom instance.
     *
     * @return Returns secure random instance.
     */
    final SecureRandom secureRandom() {
        return this.sr;
    }

	/**
     * Generate a random exponent
     * 
     * @return the generated random exponent.
     */
	final BigInteger randomExponent() {
		final byte[] sb = new byte[SM.MOD_LEN_BYTES];
		this.sr.nextBytes(sb);
		return new BigInteger(1, sb);
	}

	/**
	 * Proof of knowledge of a discrete logarithm.
     *
     * @param g the group generator
     * @param x the secret information
     * @param version the prefix to use for the hashing function
     * @return c and d.
	 * @throws SMException when c and d could not be calculated
	 */
	final BigInteger[] proofKnowLog(@Nonnull final BigInteger x, final int version) throws SM.SMException
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
            @Nonnull final BigInteger x, final int version) throws SM.SMException
	{
	    final BigInteger gd = G1.modPow(d, SM.MODULUS_S);
	    final BigInteger xc = x.modPow(c, SM.MODULUS_S);
	    final BigInteger gdxc = gd.multiply(xc).mod(SM.MODULUS_S);
	    final BigInteger hgdxc = SM.hash(version, gdxc, null);

        if (hgdxc.compareTo(c) != 0) {
            throw new SM.SMException("Proof checking failed");
        }
	}

	/**
	 * Proof of knowledge of coordinates with first components being equal
	 */
	final BigInteger[] proofEqualCoords(@Nonnull final BigInteger g2,
            @Nonnull final BigInteger g3, @Nonnull final BigInteger secret_mpi,
            @Nonnull final BigInteger r, final int version) throws SM.SMException
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
            @Nonnull final BigInteger g3, final int version) throws SM.SMException
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
            throw new SM.SMException("Proof checking failed");
        }
	}

	/**
	 * Proof of knowledge of logs with exponents being equal
	 */
	final BigInteger[] proofEqualLogs(@Nonnull final BigInteger qab,
            @Nonnull final BigInteger x3, final int version) throws SM.SMException
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
            @Nonnull final BigInteger qab, final int version) throws SM.SMException
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
            throw new SM.SMException("Proof checking failed");
        }
	}

	/**
     * Check that an BigInteger is in the right range to be a (non-unit) group
	 * element.
     *
     * @param g the BigInteger to check.
     * @throws net.java.otr4j.crypto.SM.SMException Throws SMException if check fails.
     */
	final static void checkGroupElem(@Nonnull final BigInteger g) throws SM.SMException
	{
		if(g.compareTo(BigInteger.valueOf(2)) < 0 ||
				g.compareTo(SM.MODULUS_MINUS_2) > 0) {
            throw new SM.SMException("Invalid parameter");
        }
	}

	/**
     * Check that an BigInteger is in the right range to be a (non-zero)
     * exponent.
     *
     * @param x The BigInteger to check.
     * @throws net.java.otr4j.crypto.SM.SMException Throws SMException if check fails.
     */
	final static void checkExpon(@Nonnull final BigInteger x) throws SM.SMException
	{
		if (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(SM.ORDER_S) >= 0) {
            throw new SM.SMException("Invalid parameter");
        }
	}
}

/**
 * SMP state in expectation of SMP message 1. (Or when initiating SMP
 * negotiation.)
 *
 * In this state we accept messages 1 (TLV type 2), and 1Q (TLV type 7).
 *
 * This is the initial and default state. SMP is reset to this state whenever an
 * error occurs or SMP is aborted.
 */
final class StateExpect1 extends State {

    private final SMStatus status;

    final BigInteger x2;
    final BigInteger x3;
    
    final BigInteger g2;
    final BigInteger g3;
    
    final BigInteger g3o;

    StateExpect1(@Nonnull final SecureRandom sr) {
        this(sr, SMStatus.UNDECIDED, null, null, null, null, null);
    }

    StateExpect1(@Nonnull final SecureRandom sr, @Nonnull final SMStatus status) {
        this(sr, status, null, null, null, null, null);
    }

    private StateExpect1(@Nonnull final SecureRandom sr,
            @Nonnull final SMStatus status, @Nullable final BigInteger x2,
            @Nullable final BigInteger x3, @Nullable final BigInteger g2,
            @Nullable final BigInteger g3, @Nullable final BigInteger g3o) {
        super(sr);
        this.status = status;
        this.x2 = x2;
        this.x3 = x3;
        this.g2 = g2;
        this.g3 = g3;
        this.g3o = g3o;
    }

    @Override
    SMStatus status() {
        return this.status;
    }

    @Override
    byte[] startSMP(@Nonnull final SM astate, @Nonnull final byte[] secret) throws SM.SMAbortedException, SM.SMException {
	    /* Initialize the sm state or update the secret */
	    final BigInteger secret_mpi = new BigInteger(1, secret);

        final BigInteger x2 = randomExponent();
        final BigInteger x3 = randomExponent();

	    final BigInteger[] msg1 = new BigInteger[6];
	    msg1[0] = G1.modPow(x2, SM.MODULUS_S);
	    BigInteger[] res = proofKnowLog(x2, 1);
	    msg1[1]=res[0];
	    msg1[2]=res[1];
	    
	    msg1[3] = G1.modPow(x3, SM.MODULUS_S);
	    res = proofKnowLog(x3, 2);
	    msg1[4]=res[0];
	    msg1[5]=res[1];

	    final byte[] ret = SM.serialize(msg1);
        // FIXME what to do with status CHEATED?
	    //astate.smProgState = PROG_OK;

        astate.setState(new StateExpect2(this.secureRandom(), secret_mpi, x2, x3));
	    return ret;
    }

    @Override
    void smpAbort(@Nonnull final SM state) {
        // NOOP since this is the default state already.
        // caller is expected to send type 6 TLV: SMP Abort.
        // FIXME Should we make sure status == UNDECIDED when smpAbort() is called? Or is it okay to have FAILED/SUCCEEDED, since we will reset when we start SMP exchange anew?
    }

    @Override
    void smpMessage1a(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
	    /* Initialize the sm state if needed */

        // FIXME what to do with status CHEATED?
	    //bstate.smProgState = PROG_CHEATED;

	    /* Read from input to find the mpis */
	    final BigInteger[] msg1 = SM.unserialize(input);

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg1[0]);
        checkExpon(msg1[2]);
        checkGroupElem(msg1[3]);
        checkExpon(msg1[5]);

        /* Store Alice's g3a value for later in the protocol */
        final BigInteger g3o = msg1[3];
	    
	    /* Verify Alice's proofs */
        checkKnowLog(msg1[1], msg1[2], msg1[0], 1);
        checkKnowLog(msg1[4], msg1[5], msg1[3], 2);

        /* Create Bob's half of the generators g2 and g3 */
        final BigInteger x2 = randomExponent();
        final BigInteger x3 = randomExponent();

        /* Combine the two halves from Bob and Alice and determine g2 and g3 */
        final BigInteger g2 = msg1[0].modPow(x2, SM.MODULUS_S);
	    final BigInteger g3 = msg1[3].modPow(x3, SM.MODULUS_S);
	    
        // FIXME what to do with status CHEATED?
	    //bstate.smProgState = PROG_OK;
        bstate.setState(new StateExpect1(this.secureRandom(), SMStatus.UNDECIDED, x2, x3, g2, g3, g3o));
    }

    @Override
    byte[] smpMessage1b(@Nonnull final SM bstate, @Nonnull final byte[] secret) throws SM.SMAbortedException, SM.SMException {
	    /* Convert the given secret to the proper form and store it */
		final BigInteger secret_mpi = new BigInteger(1, secret);

	    final BigInteger[] msg2 = new BigInteger[11];
	    msg2[0] = G1.modPow(x2, SM.MODULUS_S);
	    BigInteger[] res = proofKnowLog(x2, 3);
	    msg2[1]=res[0];
	    msg2[2]=res[1];

	    msg2[3] = G1.modPow(x3, SM.MODULUS_S);
	    res = proofKnowLog(x3, 4);
	    msg2[4]=res[0];
	    msg2[5]=res[1];

	    /* Calculate P and Q values for Bob */
	    final BigInteger r = randomExponent();
        final BigInteger p = g3.modPow(r, SM.MODULUS_S);
	    msg2[6] = p;
	    final BigInteger qb1 = G1.modPow(r, SM.MODULUS_S);
	    final BigInteger qb2 = g2.modPow(secret_mpi, SM.MODULUS_S);
	    final BigInteger q = qb1.multiply(qb2).mod(SM.MODULUS_S);
	    msg2[7] = q;
	    
	    res = proofEqualCoords(g2, g3, secret_mpi, r, 5);
	    msg2[8]=res[0];
	    msg2[9]=res[1];
	    msg2[10]=res[2];

        bstate.setState(new StateExpect3(this, p, q));

	    /* Convert to serialized form */
	    return SM.serialize(msg2);
    }
}

/**
 * SMP state in expectation of SMP message 2: Bob's message completing the DH
 * exchange.
 *
 * In this state we accept message 2 (TLV type 3).
 */
final class StateExpect2 extends State {

    final BigInteger secret_mpi;
    final BigInteger x2;
    final BigInteger x3;

    StateExpect2(@Nonnull final SecureRandom sr, @Nonnull final BigInteger secret_mpi,
            @Nonnull final BigInteger x2, @Nonnull final BigInteger x3) {
        super(sr);
        this.secret_mpi = secret_mpi;
        this.x2 = x2;
        this.x3 = x3;
    }

    @Override
    SMStatus status() {
        return SMStatus.UNDECIDED;
    }

    @Override
    byte[] smpMessage2(@Nonnull final SM astate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
	    /* Read from input to find the mpis */
        // FIXME what to do with status CHEATED?
	    //astate.smProgState = PROG_CHEATED;
	    
	    final BigInteger[] msg2 = SM.unserialize(input);

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg2[0]);
        checkGroupElem(msg2[3]);
        checkGroupElem(msg2[6]);
        checkGroupElem(msg2[7]);
        checkExpon(msg2[2]);
        checkExpon(msg2[5]);
        checkExpon(msg2[9]);
        checkExpon(msg2[10]);

	    final BigInteger[] msg3 = new BigInteger[8];

        /* Store Bob's g3a value for later in the protocol */
        final BigInteger g3o = msg2[3];

	    /* Verify Bob's knowledge of discreet log proofs */
        checkKnowLog(msg2[1], msg2[2], msg2[0], 3);
        checkKnowLog(msg2[4], msg2[5], msg2[3], 4);

        /* Combine the two halves from Bob and Alice and determine g2 and g3 */
        final BigInteger g2 = msg2[0].modPow(x2, SM.MODULUS_S);
        final BigInteger g3 = msg2[3].modPow(x3, SM.MODULUS_S);
	    
	    /* Verify Bob's coordinate equality proof */
	    checkEqualCoords(msg2[8], msg2[9], msg2[10], msg2[6], msg2[7], g2, g3, 5);

	    /* Calculate P and Q values for Alice */
	    final BigInteger r = randomExponent();
	    //BigInteger r = new BigInteger(SM.GENERATOR_S);

	    final BigInteger p = g3.modPow(r, SM.MODULUS_S);
	    msg3[0] = p;
	    final BigInteger qa1 = G1.modPow(r, SM.MODULUS_S);
	    final BigInteger qa2 = g2.modPow(secret_mpi, SM.MODULUS_S);
	    final BigInteger q = qa1.multiply(qa2).mod(SM.MODULUS_S);
	    msg3[1] = q;
	    
	    BigInteger[] res = proofEqualCoords(g2, g3, secret_mpi, r, 6);
	    msg3[2] = res[0];
	    msg3[3] = res[1];
	    msg3[4] = res[2];


	    /* Calculate Ra and proof */
	    BigInteger inv = msg2[6].modInverse(SM.MODULUS_S);
        final BigInteger pab = p.multiply(inv).mod(SM.MODULUS_S);
	    inv = msg2[7].modInverse(SM.MODULUS_S);
        final BigInteger qab = q.multiply(inv).mod(SM.MODULUS_S);
	    msg3[5] = qab.modPow(x3, SM.MODULUS_S);
	    res = proofEqualLogs(qab, x3, 7);
	    msg3[6]=res[0];
	    msg3[7]=res[1];
	    
	    final byte[] output = SM.serialize(msg3);

        astate.setState(new StateExpect4(this, g3o, pab, qab));

        // FIXME what to do with status CHEATED?
	    //astate.smProgState = PROG_OK;
	    return output;
    }
}

/**
 * SMP state in expectation of SMP message 3: Alice's final message in SMP
 * exchange.
 *
 * In this state we accept message 3 (TLV type 4).
 */
final class StateExpect3 extends State {

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
    SMStatus status() {
        return SMStatus.UNDECIDED;
    }

    @Override
    byte[] smpMessage3(@Nonnull final SM bstate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
	    /* Read from input to find the mpis */
	    final BigInteger[] msg3 = SM.unserialize(input);

        // FIXME create similar variable for keeping track of smProgState.
	    //bstate.smProgState = PROG_CHEATED;
	    
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
	    msg4[1]=res[0];
	    msg4[2]=res[1];
	    
	    final byte[] output = SM.serialize(msg4);

	    /* Calculate Rab and verify that secrets match */
	    
	    final BigInteger rab = msg3[5].modPow(x3, SM.MODULUS_S);
	    final int comp = rab.compareTo(pab);

        // FIXME what to do with status CHEATED?
        final SMStatus status = (comp == 0) ? SMStatus.SUCCEEDED : SMStatus.FAILED;
        bstate.setState(new StateExpect1(this.secureRandom(), status));

	    return output;
    }
}

/**
 * SMP state in expectation of SMP message 4: Bob's final message in SMP
 * exchange.
 *
 * In this state we accept message 4 (TLV type 5).
 */
final class StateExpect4 extends State {

    final BigInteger x3;
    final BigInteger g3o;
    final BigInteger pab;
    final BigInteger qab;

    StateExpect4(@Nonnull final StateExpect2 previous, @Nonnull final BigInteger g3o,
            @Nonnull final BigInteger pab, @Nonnull final BigInteger qab) {
        super(previous.secureRandom());
        this.x3 = previous.x3;
        this.g3o = g3o;
        this.pab = pab;
        this.qab = qab;
    }

    @Override
    SMStatus status() {
        return SMStatus.UNDECIDED;
    }

    @Override
    void smpMessage4(@Nonnull final SM astate, @Nonnull final byte[] input) throws SM.SMAbortedException, SM.SMException {
	    /* Read from input to find the mpis */
	    final BigInteger[] msg4 = SM.unserialize(input);
        // FIXME create similar variable for keeping track of smProgState.
	    //astate.smProgState = PROG_CHEATED;

        /* Verify parameters and let checks throw exceptions in case of failure.*/
	    checkGroupElem(msg4[0]);
        checkExpon(msg4[2]);

	    /* Verify Bob's log equality proof */
	    checkEqualLogs(msg4[1], msg4[2], msg4[0], g3o, qab, 8);

	    /* Calculate Rab and verify that secrets match */
	    
	    final BigInteger rab = msg4[0].modPow(x3, SM.MODULUS_S);
	    final int comp = rab.compareTo(pab);

        // FIXME what to do with status CHEATED?
        final SMStatus status = (comp == 0) ? SMStatus.SUCCEEDED : SMStatus.FAILED;
        astate.setState(new StateExpect1(this.secureRandom(), status));
    }
}
