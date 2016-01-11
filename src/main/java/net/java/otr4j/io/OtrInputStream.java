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
import net.java.otr4j.io.messages.SignatureX;

public class OtrInputStream extends FilterInputStream implements
		SerializationConstants {
    // TODO consider making OtrInputStream class final

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
        // TODO what to do with (signed) ints > 0x7fffffff? This will be interpreted as negative by Java.
		return value;
	}

	public int readByte() throws IOException {
		return readNumber(TYPE_LEN_BYTE);
	}

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

	public byte[] readData() throws IOException {
		final int dataLen = readNumber(DATA_LEN);
		return checkedRead(dataLen);
	}

	public PublicKey readPublicKey() throws IOException {
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
                // TODO consider including the root cause in the IOException
				throw new IOException();
			}
			try {
				return keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e) {
                // TODO consider including the root cause in the IOException
				throw new IOException();
			}
		default:
			throw new UnsupportedOperationException();
		}
	}

	public DHPublicKey readDHPublicKey() throws IOException {
		final BigInteger gyMpi = readBigInt();
		try {
			return OtrCryptoEngine.getDHPublicKey(gyMpi);
		} catch (Exception ex) {
            // TODO insert cause in IOException
			throw new IOException();
		}
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

	public SignatureX readMysteriousX() throws IOException {
		final PublicKey pubKey = readPublicKey();
		final int dhKeyID = readInt();
		final byte[] sig = readSignature(pubKey);
		return new SignatureX(pubKey, dhKeyID, sig);
	}
}
