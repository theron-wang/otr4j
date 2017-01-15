/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoException;

import org.bouncycastle.util.encoders.Base64;

import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import static net.java.otr4j.io.messages.AbstractMessage.checkCast;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureMessage;
import net.java.otr4j.io.messages.SignatureX;
import net.java.otr4j.session.Session.OTRv;

/**
 * @author George Politis
 */
public final class SerializationUtils {

    private static final Logger LOGGER = Logger.getLogger(SerializationUtils.class.getCanonicalName());

	/**
	 * Charset for base64-encoded content.
	 */
	public static final Charset ASCII = Charset.forName("US-ASCII");

	/**
	 * Charset for message content according to OTR spec.
	 */
	public static final Charset UTF8 = Charset.forName("UTF-8");

    /**
     * Index of numbers such that we can easily translate from number character
     * to integer value. We use this index as we can use this also as an index
     * of valid number characters. This avoids having to do code-table-dependent
     * checks such as c &gt;= '0' and c &lt;= '9'.
     */
    private static final String NUMBERINDEX = "0123456789";

    private SerializationUtils() {
        // Utility class cannot be instantiated.
    }

	// Mysterious X IO.
	public static SignatureX toMysteriousX(@Nonnull final byte[] b) throws IOException, OtrCryptoException {
		final ByteArrayInputStream in = new ByteArrayInputStream(b);
		final SignatureX x;
        try (OtrInputStream ois = new OtrInputStream(in)) {
            x = ois.readMysteriousX();
        }
		return x;
	}

	public static byte[] toByteArray(@Nonnull final SignatureX x) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writeMysteriousX(x);
            b = out.toByteArray();
        }
		return b;
	}

	// Mysterious M IO.
	public static byte[] toByteArray(@Nonnull final SignatureM m) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writeMysteriousX(m);
            b = out.toByteArray();
        }
		return b;
	}

	// Mysterious T IO.
	public static byte[] toByteArray(@Nonnull final MysteriousT t) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writeMysteriousT(t);
            b = out.toByteArray();
        }
		return b;
	}

	// Basic IO.
	public static byte[] writeData(@Nullable final byte[] b) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] otrb;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writeData(b);
            otrb = out.toByteArray();
        }
		return otrb;
	}

    // TODO can we simplify this such that we need not handle IOException?
	// BigInteger IO.
	public static byte[] writeMpi(@Nonnull final BigInteger bigInt) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writeBigInt(bigInt);
            b = out.toByteArray();
        }
		return b;
	}

	public static BigInteger readMpi(@Nonnull final byte[] b) throws IOException {
		final ByteArrayInputStream in = new ByteArrayInputStream(b);
		final BigInteger bigint;
        try (OtrInputStream ois = new OtrInputStream(in)) {
            bigint = ois.readBigInt();
        }
		return bigint;
	}

	// Public Key IO.
	public static byte[] writePublicKey(@Nonnull final PublicKey pubKey) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b;
        try (OtrOutputStream oos = new OtrOutputStream(out)) {
            oos.writePublicKey(pubKey);
            b = out.toByteArray();
        }
		return b;
	}

	// Message IO.
	public static String toString(@Nonnull final AbstractMessage m) throws IOException {
		final StringWriter writer = new StringWriter();
		if (m.messageType != AbstractMessage.MESSAGE_PLAINTEXT && m.messageType != AbstractMessage.MESSAGE_QUERY) {
            // We avoid writing the header until we know for sure we need it. We
            // know for sure that plaintext messages do not need it. We may not
            // need it for a query message if the versions list is empty.
            writer.write(SerializationConstants.HEAD);
        }

		switch (m.messageType) {
			case AbstractMessage.MESSAGE_ERROR:
				final ErrorMessage error = checkCast(ErrorMessage.class, m);
				writer.write(SerializationConstants.HEAD_ERROR);
				writer.write(SerializationConstants.ERROR_PREFIX);
				writer.write(error.error);
				break;
			case AbstractMessage.MESSAGE_PLAINTEXT:
				final PlainTextMessage plaintxt = checkCast(PlainTextMessage.class, m);
				writer.write(plaintxt.cleanText);
				if (!plaintxt.versions.isEmpty()) {
					writer.write(" \t  \t\t\t\t \t \t \t  ");
					for (final int version : plaintxt.versions) {
						if (version == OTRv.TWO) {
                            writer.write("  \t\t  \t ");
                        }
						if (version == OTRv.THREE) {
                            writer.write("  \t\t  \t\t");
                        }
					}
				}
				break;
			case AbstractMessage.MESSAGE_QUERY:
                final QueryMessage query = checkCast(QueryMessage.class, m);
                if (query.versions.size() == 1 && query.versions.contains(1)) {
                    throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
                }
                // TODO technically, there still a bug here, as we can end up with 0 versions after dropping invalid versions. How do we respond in that case?
                if (query.versions.size() > 0) {
                    writer.write(SerializationConstants.HEAD);
                    writer.write(SerializationConstants.HEAD_QUERY_V);
                    final ArrayList<Integer> versions = new ArrayList(query.versions);
                    versions.sort(null);
                    for (final int version : versions) {
                        if (version <= 1 || version > 9) {
                            LOGGER.log(Level.WARNING, "Encountered illegal OTR version: {0}. Versions 1 and lower and over 9 are not supported. This version will be skipped. If you see this message, there is likely a bug in otr4j.", version);
                            continue;
                        }
                        writer.write(NUMBERINDEX.charAt(version));
                    }
                    writer.write(SerializationConstants.HEAD_QUERY_Q);
                }
                break;
			case AbstractEncodedMessage.MESSAGE_DHKEY:
			case AbstractEncodedMessage.MESSAGE_REVEALSIG:
			case AbstractEncodedMessage.MESSAGE_SIGNATURE:
			case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
			case AbstractEncodedMessage.MESSAGE_DATA:
				final ByteArrayOutputStream o = new ByteArrayOutputStream();
				final OtrOutputStream s = new OtrOutputStream(o);

				switch (m.messageType) {
					case AbstractEncodedMessage.MESSAGE_DHKEY:
						final DHKeyMessage dhkey = checkCast(DHKeyMessage.class, m);
						s.writeShort(dhkey.protocolVersion);
						s.writeByte(dhkey.messageType);
						if (dhkey.protocolVersion == OTRv.THREE) {
							s.writeInt(dhkey.senderInstanceTag);
							s.writeInt(dhkey.receiverInstanceTag);
						}
						s.writeDHPublicKey(dhkey.dhPublicKey);
						break;
					case AbstractEncodedMessage.MESSAGE_REVEALSIG:
						final RevealSignatureMessage revealsig = checkCast(RevealSignatureMessage.class, m);
						s.writeShort(revealsig.protocolVersion);
						s.writeByte(revealsig.messageType);
						if (revealsig.protocolVersion == OTRv.THREE) {
							s.writeInt(revealsig.senderInstanceTag);
							s.writeInt(revealsig.receiverInstanceTag);
						}
						s.writeData(revealsig.revealedKey);
						s.writeData(revealsig.xEncrypted);
						s.writeMac(revealsig.xEncryptedMAC);
						break;
					case AbstractEncodedMessage.MESSAGE_SIGNATURE:
						final SignatureMessage sig = checkCast(SignatureMessage.class, m);
						s.writeShort(sig.protocolVersion);
						s.writeByte(sig.messageType);
						if (sig.protocolVersion == OTRv.THREE) {
							s.writeInt(sig.senderInstanceTag);
							s.writeInt(sig.receiverInstanceTag);
						}
						s.writeData(sig.xEncrypted);
						s.writeMac(sig.xEncryptedMAC);
						break;
					case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
						final DHCommitMessage dhcommit = checkCast(DHCommitMessage.class, m);
						s.writeShort(dhcommit.protocolVersion);
						s.writeByte(dhcommit.messageType);
						if (dhcommit.protocolVersion == OTRv.THREE) {
							s.writeInt(dhcommit.senderInstanceTag);
							s.writeInt(dhcommit.receiverInstanceTag);
						}
						s.writeData(dhcommit.dhPublicKeyEncrypted);
						s.writeData(dhcommit.dhPublicKeyHash);
						break;
					case AbstractEncodedMessage.MESSAGE_DATA:
						final DataMessage data = checkCast(DataMessage.class, m);
						s.writeShort(data.protocolVersion);
						s.writeByte(data.messageType);
						if (data.protocolVersion == OTRv.THREE) {
							s.writeInt(data.senderInstanceTag);
							s.writeInt(data.receiverInstanceTag);
						}
						s.writeByte(data.flags);
						s.writeInt(data.senderKeyID);
						s.writeInt(data.recipientKeyID);
						s.writeDHPublicKey(data.nextDH);
						s.writeCtr(data.ctr);
						s.writeData(data.encryptedMessage);
						s.writeMac(data.mac);
						s.writeData(data.oldMACKeys);
						break;
                    default:
                        break;
				}

				writer.write(SerializationConstants.HEAD_ENCODED);
				writer.write(new String(Base64.encode(o.toByteArray()), ASCII));
				writer.write(".");
				break;
			default:
				throw new IOException("Illegal message type.");
		}

		return writer.toString();
	}

    // PATTERN_WHITESPACE recognizes OTR v1, v2 and v3 whitespace tags. We will
    // continue to recognize OTR v1 whitespace tag for compatibility purposes
    // and to avoid bad interpretation.
	private static final Pattern PATTERN_WHITESPACE = Pattern
			.compile(" \\t  \\t\\t\\t\\t \\t \\t \\t  ( \\t \\t  \\t )?(  \\t\\t  \\t )?(  \\t\\t  \\t\\t)?");

	/**
	 * Parses an encoded OTR string into an instance of {@link AbstractMessage}.
	 *
	 * @param s
	 *            the string to parse
	 * @return the parsed message
	 * @throws IOException
	 *             error parsing the string to a message, either format mismatch
	 *             or real IO error
     * @throws net.java.otr4j.crypto.OtrCryptoException error of cryptographic nature
	 */
	public static AbstractMessage toMessage(@Nullable final String s) throws IOException, OtrCryptoException {
		if (s == null || s.length() == 0) {
            return null;
        }

		final int idxHead = s.indexOf(SerializationConstants.HEAD);
		if (idxHead > -1) {
			// Message **contains** the string "?OTR". Check to see if it is an error message, a query message or a data
			// message.

			final char contentType = s.charAt(idxHead + SerializationConstants.HEAD.length());
			String content = s
					.substring(idxHead + SerializationConstants.HEAD.length() + 1);

			if (contentType == SerializationConstants.HEAD_ERROR
					&& content.startsWith(SerializationConstants.ERROR_PREFIX)) {
				// Error tag found.

				content = content.substring(idxHead + SerializationConstants.ERROR_PREFIX
						.length());
				return new ErrorMessage(AbstractMessage.MESSAGE_ERROR, content);
			} else if (contentType == SerializationConstants.HEAD_QUERY_V
					|| contentType == SerializationConstants.HEAD_QUERY_Q) {
				// Query tag found.
				final String versionString;
                if (SerializationConstants.HEAD_QUERY_Q == contentType
                        && content.length() > 0 && content.charAt(0) == 'v') {
                    // OTR v1 query tag format. However, we do not active
                    // support OTRv1 anymore. Therefore the logic only supports
                    // skipping over the OTRv1 tags in order to reach OTR v2 and
                    // v3 version tags.
                    versionString = content.substring(1, content.indexOf('?'));
				} else if (SerializationConstants.HEAD_QUERY_V == contentType) {
                    // OTR v2+ query tag format.
					versionString = content.substring(0, content.indexOf('?'));
				} else {
                    versionString = "";
                }
                final HashSet<Integer> versions = new HashSet<>();
                final StringReader sr = new StringReader(versionString);
                int c;
                while ((c = sr.read()) != -1) {
                    final int idx = NUMBERINDEX.indexOf(c);
                    if (idx > -1) {
                        versions.add(idx);
                    }
                }
				return new QueryMessage(versions);
			} else if (idxHead == 0 && contentType == SerializationConstants.HEAD_ENCODED) {
				// Data message found.

                /*
                 * BC 1.48 added a check to throw an exception if a non-base64 character is encountered.
                 * An OTR message consists of ?OTR:AbcDefFe. (note the terminating point).
                 * Otr4j doesn't strip this point before passing the content to the base64 decoder.
                 * So in order to decode the content string we have to get rid of the '.' first.
                 */
                // TODO here an assumption is being made that the last character is a '.' Should we check before acting on this?
				final ByteArrayInputStream bin = new ByteArrayInputStream(Base64
						.decode(content.substring(0, content.length() - 1).getBytes(ASCII)));
				// We have an encoded message.
				try (final OtrInputStream otr = new OtrInputStream(bin)) {
                    // FIXME it seems we do not check message's protocol version with policy of allowed versions. What's that about?
					final int protocolVersion = otr.readShort();
					if (!OTRv.ALL.contains(protocolVersion)) {
						throw new IOException("Unsupported protocol version "
								+ protocolVersion);
					}
					final int messageType = otr.readByte();
					int senderInstanceTag = 0;
					int recipientInstanceTag = 0;
					if (protocolVersion == OTRv.THREE) {
						senderInstanceTag = otr.readInt();
						recipientInstanceTag = otr.readInt();
					}
					switch (messageType) {
						case AbstractEncodedMessage.MESSAGE_DATA:
							final int flags = otr.readByte();
							final int senderKeyID = otr.readInt();
							final int recipientKeyID = otr.readInt();
							final DHPublicKey nextDH = otr.readDHPublicKey();
							final byte[] ctr = otr.readCtr();
							final byte[] encryptedMessage = otr.readData();
							final byte[] mac = otr.readMac();
							final byte[] oldMacKeys = otr.readData();
							final DataMessage dataMessage =
									new DataMessage(protocolVersion, flags, senderKeyID,
									recipientKeyID, nextDH, ctr, encryptedMessage, mac,
									oldMacKeys);
							dataMessage.senderInstanceTag = senderInstanceTag;
							dataMessage.receiverInstanceTag = recipientInstanceTag;
							return dataMessage;
						case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
							final byte[] dhPublicKeyEncrypted = otr.readData();
							final byte[] dhPublicKeyHash = otr.readData();
							final DHCommitMessage dhCommitMessage =
									new DHCommitMessage(protocolVersion,
											dhPublicKeyHash, dhPublicKeyEncrypted);
							dhCommitMessage.senderInstanceTag = senderInstanceTag;
							dhCommitMessage.receiverInstanceTag = recipientInstanceTag;
							return dhCommitMessage;
						case AbstractEncodedMessage.MESSAGE_DHKEY:
							final DHPublicKey dhPublicKey = otr.readDHPublicKey();
                            final DHKeyMessage dhKeyMessage = new DHKeyMessage(protocolVersion, dhPublicKey);
							dhKeyMessage.senderInstanceTag = senderInstanceTag;
							dhKeyMessage.receiverInstanceTag = recipientInstanceTag;
							return dhKeyMessage;
						case AbstractEncodedMessage.MESSAGE_REVEALSIG: {
							final byte[] revealedKey = otr.readData();
							final byte[] xEncrypted = otr.readData();
							final byte[] xEncryptedMac = otr.readMac();
							final RevealSignatureMessage revealSignatureMessage =
									new RevealSignatureMessage(protocolVersion,
											xEncrypted, xEncryptedMac, revealedKey);
							revealSignatureMessage.senderInstanceTag = senderInstanceTag;
							revealSignatureMessage.receiverInstanceTag = recipientInstanceTag;
							return revealSignatureMessage;
						}
						case AbstractEncodedMessage.MESSAGE_SIGNATURE: {
							final byte[] xEncryted = otr.readData();
							final byte[] xEncryptedMac = otr.readMac();
                            return new SignatureMessage(protocolVersion, xEncryted,
                                    xEncryptedMac, senderInstanceTag, recipientInstanceTag);
						}
						default:
							// NOTE by gp: aren't we being a little too harsh here? Passing the message as a plaintext
							// message to the host application shouldn't hurt anybody.
							throw new IOException("Illegal message type.");
					}
				}
			}
		}

		// Try to detect whitespace tag.
		final Matcher matcher = PATTERN_WHITESPACE.matcher(s);

		boolean v2 = false;
		boolean v3 = false;
		while (matcher.find()) {
            // Ignore group 1 (OTRv1 tag) as V1 is not supported anymore.
			if (!v2 && matcher.start(2) > -1) {
                v2 = true;
            }
			if (!v3 && matcher.start(3) > -1) {
                v3 = true;
            }
			if (v2 && v3) {
                break;
            }
		}

		final String cleanText = matcher.replaceAll("");
        final HashSet<Integer> versions = new HashSet<>();
        if (v2) {
            versions.add(OTRv.TWO);
        }
        if (v3) {
            versions.add(OTRv.THREE);
        }
        return new PlainTextMessage(versions, cleanText);
	}

	private static final char HEX_ENCODER[] = {'0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	public static String byteArrayToHexString(@Nullable final byte in[]) {
		if (in == null || in.length <= 0) {
            return null;
        }
		final StringBuilder out = new StringBuilder(in.length * 2);
		int i = 0;
		while (i < in.length) {
			out.append(HEX_ENCODER[(in[i] >>> 4) & 0x0F]);
			out.append(HEX_ENCODER[in[i] & 0x0F]);
			i++;
		}
		return out.toString();
	}

	private static final String HEX_DECODER = "0123456789ABCDEF";

	public static byte[] hexStringToByteArray(@Nonnull String value) {
		value = value.toUpperCase(Locale.US);
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (int index = 0; index < value.length(); index += 2) {
			int high = HEX_DECODER.indexOf(value.charAt(index));
			int low = HEX_DECODER.indexOf(value.charAt(index + 1));
			out.write((high << 4) + low);
		}
		return out.toByteArray();
	}

	/**
     * Convert the {@code String} text to a {@code byte[]}, including sanitizing
     * it to make sure no corrupt characters conflict with bytes that have
     * special meaning in OTR. Mostly, this means removing NULL bytes, since
     * {@code 0x00) is used as the separator between the message and the TLVs
     * in an OTR Data Message.
     *
     * @param msg the plain text message being sent
     * @return byte[] the incoming message converted to OTR-safe bytes
     */
    public static byte[] convertTextToBytes(@Nonnull final String msg) {
        return msg.replace('\0', '?').getBytes(SerializationUtils.UTF8);
    }

	/**
	 * Check whether the provided content is OTR encoded.
	 *
	 * @param content
	 *            the content to investigate
	 * @return returns true if content is OTR encoded, or false otherwise
	 */
	public static boolean otrEncoded(@Nonnull final String content) {
		return content.startsWith(SerializationConstants.HEAD
				+ SerializationConstants.HEAD_ENCODED);
	}
}