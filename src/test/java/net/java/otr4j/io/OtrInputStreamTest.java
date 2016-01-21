package net.java.otr4j.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for OtrInputStream.
 *
 * Some of these tests are set up to test the limitations of (signed) ints in
 * otr4j implementation.
 *
 * @author Danny van Heumen
 */
public class OtrInputStreamTest {

    @Test
    public void testDataLengthOkay() throws IOException {
        final byte[] data = new byte[] { 0, 0, 0, 1, 0x6a };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertArrayEquals(new byte[] { 0x6a }, ois.readData());
    }

    @Test(expected = OtrInputStream.UnsupportedLengthException.class)
    public void testDataLengthTooLarge() throws IOException {
        // Verify that the limitation of Java's signed int is in place as
        // expected. 0xffffffff is too large and would have been interpreted as
        // a negative value, thus a negative array size for the byte[]
        // containing the upcoming data.
        // Here we verify that the predefined exception for this particular case
        // is thrown to signal the occurrence of a data value that is too large
        // for otr4j to handle. (This is a limitation of otr4j.)
        final byte[] data = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        ois.readData();
    }

    @Test
    public void testReadByte() throws IOException {
        final byte[] data = new byte[] { 0x20 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(' ', ois.readByte());
    }

    @Test(expected = IOException.class)
    public void testReadByteEmptyBuffer() throws IOException {
        final byte[] data = new byte[0];
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        ois.readByte();
    }

    @Test(expected = IOException.class)
    public void testReadIntInsufficientData() throws IOException {
        final byte[] data = new byte[] { 0x1, 0x2, 0x3 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        ois.readInt();
    }

    @Test
    public void testReadInt() throws IOException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x10 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(16, ois.readInt());
        assertEquals(0, ois.available());
    }

    @Test
    public void testReadIntDataLeft() throws IOException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x10, 0x3f};
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(16, ois.readInt());
        assertEquals(1, ois.available());
    }

    @Test
    public void testReadShorts() throws IOException {
        final byte[] data = new byte[] { 0x0, 0x0, 0xf, 0x0, 0x3f};
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(0, ois.readShort());
        assertEquals(3840, ois.readShort());
        assertEquals(1, ois.available());
    }

    @Test
    public void testReadCounter() throws IOException {
        final byte[] data = new byte[] { 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertArrayEquals(data, ois.readCtr());
    }

    @Test
    public void testReadMAC() throws IOException {
        final byte[] data = new byte[] { 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertArrayEquals(data, ois.readMac());
    }

    @Test
    public void testReadBigInteger() throws IOException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x1, 0x55 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(BigInteger.valueOf(85l), ois.readBigInt());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testReadBadPublicKeyType() throws IOException, OtrCryptoException {
        final byte[] data = new byte[] { 0x0, 0x55 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(BigInteger.valueOf(85l), ois.readPublicKey());
    }

    @Test
    public void testReadPUblicKeyType() throws IOException, OtrCryptoException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x1, 0x2, 0x0, 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, 0x0, 0x1, 0x4 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        final PublicKey key = ois.readPublicKey();
        assertNotNull(key);
    }

    @Test
    public void testReadDHPublicKeyType() throws IOException, OtrCryptoException {
        final byte[] data = new byte[] { 0x0, 0x0, 0x0, 0x1, 0x55 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertEquals(OtrCryptoEngine.getDHPublicKey(BigInteger.valueOf(0x55)), ois.readDHPublicKey());
    }

    @Test(expected = IOException.class)
    public void testReadBadDHPublicKeyType() throws IOException, OtrCryptoException {
        final byte[] data = new byte[] { 0x0, 0x0 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        ois.readDHPublicKey();
    }

    @Test
    public void testReadTLV() throws IOException {
        final byte[] data = new byte[] { 0x0, 0x2, 0x1, 0x2 };
        final OtrInputStream ois = new OtrInputStream(new ByteArrayInputStream(data));
        assertArrayEquals(new byte[] { 0x1, 0x2 }, ois.readTlvData());
    }

    // TODO add tests for readSignature

    // TODO add tests for readMysteriousX
}
