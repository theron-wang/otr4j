/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import static net.java.otr4j.crypto.ed448.Shake256.shake256;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class Shake256Test {

    @Test(expected = NullPointerException.class)
    public void testShake256NullInput() {
        shake256(114, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testShake256NegativeSize() {
        shake256(-1, new byte[] {'H', 'e', 'l', 'l', 'o'});
    }

    @Test
    public void testShake256ZeroSize() {
        assertArrayEquals(new byte[0], shake256(0, new byte[] {'H', 'e', 'l', 'l', 'o'}));
    }

    @Test
    public void testShake256ValidLength() {
        final byte[] expected = new byte[] {85, 87, -106, -55, 11, -5, -113, 50, 86, -95, -53, 13, 126, 87, 72, 119, -3, 72, 117, 14, 65, 71, -49, 64, -86, 67, -38, 18, 43, 77, 100, -38, -2, -64, 10, -49, 31, -11, -97, 76};
        final byte[] result = shake256(40, new byte[] {'H', 'e', 'l', 'l', 'o'});
        assertEquals(40, result.length);
        assertArrayEquals(expected, result);
    }
}