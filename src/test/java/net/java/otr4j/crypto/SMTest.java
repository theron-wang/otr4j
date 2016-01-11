package net.java.otr4j.crypto;

import java.math.BigInteger;
import org.junit.Test;

/**
 * Tests for Socialist Millionaire Protocol.
 *
 * @author Danny van Heumen
 */
public class SMTest {

    @Test
    public void testCheckGroupElemValid() throws SM.SMException {
        SM.checkGroupElem(BigInteger.TEN);
    }

    @Test
    public void testCheckGroupElemJustValidLowerBound() throws SM.SMException {
        SM.checkGroupElem(BigInteger.valueOf(2l));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooSmall() throws SM.SMException {
        SM.checkGroupElem(BigInteger.ONE);
    }

    @Test
    public void testCheckGroupElemJustValidUpperBound() throws SM.SMException {
        SM.checkGroupElem(SM.MODULUS_MINUS_2);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckGroupElemTooLarge() throws SM.SMException {
        SM.checkGroupElem(SM.MODULUS_MINUS_2.add(BigInteger.ONE));
    }

    @Test
    public void testCheckExponValid() throws SM.SMException {
        SM.checkExpon(BigInteger.TEN);
    }

    @Test
    public void testCheckExponJustValidLowerBound() throws SM.SMException {
        SM.checkExpon(BigInteger.ONE);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooSmall() throws SM.SMException {
        SM.checkExpon(BigInteger.ZERO);
    }

    @Test
    public void testCheckExponJustValidUpperBound() throws SM.SMException {
        SM.checkExpon(SM.ORDER_S.subtract(BigInteger.ONE));
    }

    @Test(expected = SM.SMException.class)
    public void testCheckExponTooLarge() throws SM.SMException {
        SM.checkExpon(SM.ORDER_S);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckKnowLog() throws SM.SMException {
        SM.checkKnowLog(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualCoords() throws SM.SMException {
        final SM.SMState state = new SM.SMState();
        state.g1 = state.g2 = state.g3 = BigInteger.ONE;
        SM.checkEqualCoords(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), BigInteger.valueOf(50L), state, 0);
    }

    @Test(expected = SM.SMException.class)
    public void testCheckEqualLogs() throws SM.SMException {
        final SM.SMState state = new SM.SMState();
        state.g1 = state.g3o = state.qab = BigInteger.ONE;
        SM.checkEqualLogs(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, state, 0);
    }
}
