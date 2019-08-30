/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.UnsupportedTypeException;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.session.smp.DSAPublicKeys.fingerprint;
import static org.junit.Assert.assertArrayEquals;

@SuppressWarnings("ConstantConditions")
public class DSAPublicKeysTest {

    @Test(expected = NullPointerException.class)
    public void testFingerprint() {
        fingerprint(null);
    }

    @Test
    public void testFingerprintPublicKey() throws ProtocolException, OtrCryptoException, UnsupportedTypeException {
        final byte[] expected = {7, -17, 107, 80, -35, 40, -14, -120, -126, 20, 126, -48, -78, 25, 41, -88, -8, 91, 36, -104};
        final DSAPublicKey publicKey = new OtrInputStream(new byte[]{0, 0, 0, 0, 0, -128, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57, 0, 0, 0, 20, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11, 0, 0, 0, -128, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42, 0, 0, 0, -128, 6, 1, 92, 107, -32, 91, -93, 56, 94, 91, 100, 94, 40, 33, -94, -96, 94, -51, -53, 83, 110, 73, 67, -104, -75, -20, -81, -22, -49, -68, 19, -77, -111, -118, -37, -34, -32, 52, 91, 114, -90, 53, -62, 70, -75, -124, -34, 69, -56, 115, -63, 74, 15, -92, 2, -4, -77, 93, -103, -4, 78, 32, -64, 24, -86, 38, -47, 12, 107, 94, 29, 13, 100, 65, 81, 100, -69, 29, -24, 23, -28, -49, -31, -100, 98, -68, 58, -41, 93, 68, 98, -89, 122, 21, -23, 122, -75, 120, -70, 123, -105, 29, -62, 20, -16, -82, -61, 32, -96, 43, 29, -90, 110, 11, -119, -33, 122, -73, -112, 85, 33, 116, 69, -22, 87, -75, -24, 53}).readPublicKey();
        assertArrayEquals(expected, fingerprint(publicKey));
    }
}