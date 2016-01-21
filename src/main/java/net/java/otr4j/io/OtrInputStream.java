package net.java.otr4j.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.SignatureX;

public class OtrInputStream extends FilterInputStream implements
		SerializationConstants {

	public OtrInputStream(final InputStream in) {
		super(in);
	}

	/**
	 * Reads from the stream while checking possible border and error conditions
	 * like a requested size of zero or the stream does not contain enough data.
	 *
	 * @param length
	 *            amount of bytes to read from the stream
	 * @return the read bytes
	 * @throws IOException
	 *             the exact amount of requested bytes could not be read from
	 *             the stream.
	 */
	private byte[] checkedRead(final int length) throws IOException {
		if (length == 0) {
			return new byte[0];
		}
		final byte[] b = new byte[length];
		final int bytesRead = read(b);
		if (bytesRead != length) {
			throw new IOException(
					"Unable to read the required amount of bytes from the stream. Expected were "
							+ length + " bytes but I could only read "
							+ bytesRead + " bytes.");
		}
		return b;
	}

	private int readNumber(final int length) throws IOException {
		final byte[] b = checkedRead(length);

		int value = 0;
		for (int i = 0; i < b.length; i++) {
			final int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}

		return value;
	}

	public int readByte() throws IOException {
		return readNumber(TYPE_LEN_BYTE);
	}

    /**
     * Read an integer value from OtrInputStream.
     *
     * NOTE that OTR specifies 4-byte unsigned int values are supported.
     * However, Java by default interprets these values as signed. When using
     * readInt, make sure that your use case will consider negative values and
     * interpret them correctly.
     *
     * @return Returns int value as read from input stream.
     * @throws IOException Throws IOException in case of read errors.
     */
    public int readInt() throws IOException {
        return readNumber(TYPE_LEN_INT);
    }

	public int readShort() throws IOException {
		return readNumber(TYPE_LEN_SHORT);
	}

	public byte[] readCtr() throws IOException {
		return checkedRead(TYPE_LEN_CTR);
	}

	public byte[] readMac() throws IOException {
		return checkedRead(TYPE_LEN_MAC);
	}

	public BigInteger readBigInt() throws IOException {
		final byte[] b = readData();
		return new BigInteger(1, b);
	}

    /**
     * Read data (bytes) from OtrInputStream.
     *
     * NOTE that at this time, the maximum data length supported by otr4j is
     * limited by the Java max. integer size. Data lengths that use full 32
     * bits, will be interpreted as negative values and furthermore array are
     * limited (approx.) to {@link Integer#MAX_VALUE} length. Therefore, any
     * data of length > {@link Integer#MAX_VALUE} will be rejected and
     * {@link UnsupportedLengthException} is thrown.
     *
     * @return Returns byte[] with data read.
     * @throws IOException Throws IOException in case of read errors.
     * @throws UnsupportedLengthException Throws UnsupportedLengthException in
     * case of data with length > {@link Integer#MAX_VALUE}, as this is
     * currently unsupported by otr4j.
     */
	public byte[] readData() throws IOException {
        final int dataLen = readNumber(DATA_LEN);
        if (dataLen < 0) {
            throw new UnsupportedLengthException(dataLen);
        }
        return checkedRead(dataLen);
	}

	public PublicKey readPublicKey() throws IOException, OtrCryptoException {
		final int type = readShort();
		switch (type) {
		case 0:
			final BigInteger p = readBigInt();
			final BigInteger q = readBigInt();
			final BigInteger g = readBigInt();
			final BigInteger y = readBigInt();
			final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
			final KeyFactory keyFactory;
			try {
				keyFactory = KeyFactory.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
                throw new OtrCryptoException(e);
			}
			try {
				return keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e) {
				throw new OtrCryptoException(e);
			}
		default:
			throw new UnsupportedOperationException();
		}
	}

	public DHPublicKey readDHPublicKey() throws IOException, OtrCryptoException {
		final BigInteger gyMpi = readBigInt();
        return OtrCryptoEngine.getDHPublicKey(gyMpi);
	}

	public byte[] readTlvData() throws IOException {
		final int len = readNumber(TYPE_LEN_SHORT);
		return checkedRead(len);
	}

	public byte[] readSignature(final PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA")) {
            throw new UnsupportedOperationException();
        }

		final DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		final DSAParams dsaParams = dsaPubKey.getParams();
		return checkedRead(dsaParams.getQ().bitLength() / 4);
	}

	public SignatureX readMysteriousX() throws IOException, OtrCryptoException {
		final PublicKey pubKey = readPublicKey();
		final int dhKeyID = readInt();
		final byte[] sig = readSignature(pubKey);
		return new SignatureX(pubKey, dhKeyID, sig);
	}

    public static final class UnsupportedLengthException extends IOException {

        private static final long serialVersionUID = 3929379089911298862L;

        private UnsupportedLengthException(final int length) {
            super("An unsupported length is encountered. This is a limitation in the current implementation of otr4j. (Length: " + length + ", should be interpreted as an unsigned int.)");
        }
    }
}
