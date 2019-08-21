/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.OtrEncodables.encode;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.assertArrayEquals;

@SuppressWarnings("ConstantConditions")
public final class OtrEncodablesTest {

    @Test(expected = NullPointerException.class)
    public void testOtrEncodablesEncodeNull() {
        encode(null);
    }

    @Test
    public void testOtrEncodablesEncode() {
        final byte[] data = "Hello World!".getBytes(UTF_8);
        final byte[] expected = concatenate(new byte[]{0x00, 0x00, 0x00, 0xc}, data);
        assertArrayEquals(expected, encode(new OtrEncodable() {
            @Override
            public void writeTo(final OtrOutputStream out) {
                out.writeData(data);
            }
        }));
    }
}
