/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.crypto;

import org.junit.Test;

public class OtrCryptoExceptionTest {

    public OtrCryptoExceptionTest() {
    }

    @Test
    public void testInstantiationWithCause() {
        new OtrCryptoException(new IllegalStateException());
    }

    @Test
    public void testInstantiationWithoutCause() {
        new OtrCryptoException(null);
    }
}
