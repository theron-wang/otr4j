package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static nl.dannyvanheumen.joldilocks.Ed448.P;
import static org.junit.Assert.assertArrayEquals;

@SuppressWarnings("ConstantConditions")
public class OtrCryptoEngine4Test {

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullDestination() {
        OtrCryptoEngine4.fingerprint(null, Points.identity());
    }

    @Test(expected = NullPointerException.class)
    public void testFingerprintNullPoint() {
        OtrCryptoEngine4.fingerprint(new byte[OtrCryptoEngine4.FINGERPRINT_LENGTH_BYTES], null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationZeroSize() {
        OtrCryptoEngine4.fingerprint(new byte[0], Points.identity());
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testFingerprintDestinationTooSmall() {
        OtrCryptoEngine4.fingerprint(new byte[55], Points.identity());
    }

    @Test
    public void testFingerprintDestinationTooLarge() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31, 0};
        final byte[] dst = new byte[57];
        OtrCryptoEngine4.fingerprint(dst, P);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testFingerprint() {
        final byte[] expected = new byte[]{-69, -21, 118, -79, 110, -32, -77, -4, 19, -103, -110, -55, 46, -56, 30, -71, -32, -2, 49, -100, -45, 81, -94, -49, 116, 95, 61, 12, 72, 57, 100, 112, -7, -82, -18, 111, 107, 99, 16, -94, -57, -100, -126, -114, 117, -89, 24, -10, 67, 22, -96, -57, -103, 73, -128, 31};
        final byte[] dst = new byte[OtrCryptoEngine4.FINGERPRINT_LENGTH_BYTES];
        OtrCryptoEngine4.fingerprint(dst, P);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullDestination() {
        final byte[] input = "someinput".getBytes(StandardCharsets.US_ASCII);
        OtrCryptoEngine4.kdf1(null, 0, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf1NullInput() {
        final byte[] dst = new byte[100];
        OtrCryptoEngine4.kdf1(dst, 0, null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        OtrCryptoEngine4.kdf1(new byte[1], 0, input);
    }

    @Test
    public void testKdf1DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 0};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_1_LENGTH_BYTES + 1];
        OtrCryptoEngine4.kdf1(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_1_LENGTH_BYTES + 1];
        OtrCryptoEngine4.kdf1(dst, 1, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf1() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_1_LENGTH_BYTES];
        OtrCryptoEngine4.kdf1(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf1WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_1_LENGTH_BYTES];
        OtrCryptoEngine4.kdf1(dst, 1, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullDestination() {
        final byte[] input = "someinput".getBytes(StandardCharsets.US_ASCII);
        OtrCryptoEngine4.kdf2(null, 0, input);
    }

    @Test(expected = NullPointerException.class)
    public void testKdf2NullInput() {
        final byte[] dst = new byte[100];
        OtrCryptoEngine4.kdf2(dst, 0, null);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2DestinationTooSmall() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        OtrCryptoEngine4.kdf2(new byte[1], 0, input);
    }

    @Test
    public void testKdf2DestinationTooLarge() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11, 0};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_2_LENGTH_BYTES + 1];
        OtrCryptoEngine4.kdf2(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2DestinationTooLargeWithOffset() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {0, 86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_2_LENGTH_BYTES + 1];
        OtrCryptoEngine4.kdf2(dst, 1, input);
        assertArrayEquals(expected, dst);
    }

    @Test
    public void testKdf2() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] expected = new byte[] {86, -115, 47, 107, -116, -45, -27, -54, -26, 40, 0, -122, 79, -52, 55, 84, 121, 32, 64, -108, -124, -65, -52, -125, 101, -35, 37, 110, 88, 91, -52, 108, 82, 15, -101, -65, -70, 57, -87, 63, 52, -28, -120, 54, -82, 75, 67, 66, 103, -37, 26, 68, -8, 86, -97, -15, -117, 111, 58, 2, 82, -60, 68, 11};
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_2_LENGTH_BYTES];
        OtrCryptoEngine4.kdf2(dst, 0, input);
        assertArrayEquals(expected, dst);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testKdf2WithOffsetTooSmall() {
        final byte[] input = "helloworld".getBytes(StandardCharsets.US_ASCII);
        final byte[] dst = new byte[OtrCryptoEngine4.KDF_2_LENGTH_BYTES];
        OtrCryptoEngine4.kdf2(dst, 1, input);
    }
}
