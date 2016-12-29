/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import org.junit.Test;

public class OtrExceptionTest {

    public OtrExceptionTest() {
    }

    @Test
    public void testInstantiationWithMessage() {
        new OtrException("Hello world, problem happened!");
    }

    @Test
    public void testInstantiationWithCause() {
        new OtrException(new IllegalStateException("something bad"));
    }

    @Test
    public void testAllowInstantiationWithNullCause() {
        new OtrException((Exception) null);
    }

    @Test
    public void testAllowInstantiationWithNullMessage() {
        new OtrException((String) null);
    }
}
