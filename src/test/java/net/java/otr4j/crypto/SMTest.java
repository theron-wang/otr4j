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
}
