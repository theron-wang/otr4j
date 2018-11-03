/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

import net.java.otr4j.api.TLV;

import javax.annotation.Nonnull;
import java.io.StringWriter;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.EncodingConstants.ERROR_PREFIX;
import static net.java.otr4j.io.EncodingConstants.HEAD;
import static net.java.otr4j.io.EncodingConstants.HEAD_ENCODED;
import static net.java.otr4j.io.EncodingConstants.HEAD_ERROR;
import static org.bouncycastle.util.encoders.Base64.toBase64String;

/**
 * @author George Politis
 */
// FIXME SerializationUtils is now reduced to serializing OTR messages only. Make this into a dedicated class with suitable name.
public final class SerializationUtils {

    /**
     * Null-byte indicating end of normal message payload and start of (optional) TLV records.
     */
    private static final int TLV_DATA_START_BYTE = 0x00;

    private SerializationUtils() {
        // Utility class cannot be instantiated.
    }

    /**
     * Serialize a Message into a string-representation.
     *
     * @param m the message
     * @return Returns the string-representation of the provided message.
     */
    // Message IO.
    @Nonnull
    public static String toString(@Nonnull final Message m) {
        final StringWriter writer = new StringWriter();
        if (!(m instanceof PlainTextMessage) && !(m instanceof QueryMessage)) {
            // We avoid writing the header until we know for sure we need it. We
            // know for sure that plaintext messages do not need it. We may not
            // need it for a query message if the versions list is empty.
            writer.write(HEAD);
        }

        if (m instanceof ErrorMessage) {
            writer.write(HEAD_ERROR);
            writer.write(ERROR_PREFIX);
            writer.write(((ErrorMessage) m).error);
        } else if (m instanceof PlainTextMessage) {
            final PlainTextMessage plaintxt = (PlainTextMessage) m;
            writer.write(plaintxt.getCleanText());
            writer.write(plaintxt.getTag());
        } else if (m instanceof QueryMessage) {
            final QueryMessage query = (QueryMessage) m;
            if (query.getVersions().size() == 1 && query.getVersions().contains(1)) {
                throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
            }
            writer.write(query.getTag());
        } else if (m instanceof OtrEncodable) {
            writer.write(HEAD_ENCODED);
            final byte[] otrEncodedMessage = new OtrOutputStream().write((OtrEncodable) m).toByteArray();
            writer.write(toBase64String(otrEncodedMessage));
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }

    /**
     * Extract message contents from decrypted message bytes.
     *
     * @param messageBytes Bytes of the message (decrypted)
     * @return Returns Content instances containing both the message content
     * and any TLVs that are extracted.
     * @throws ProtocolException In case of incomplete or bad message bytes.
     */
    @Nonnull
    public static Content extractContents(@Nonnull final byte[] messageBytes) throws ProtocolException {

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = messageBytes.length;
        for (int i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] == TLV_DATA_START_BYTE) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String message = new String(messageBytes, 0, tlvIndex, UTF_8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final ArrayList<TLV> tlvs = new ArrayList<>();
        tlvIndex++; // to ignore the null value that separates message from TLVs
        if (tlvIndex < messageBytes.length) {
            final byte[] tlvsb = new byte[messageBytes.length - tlvIndex];
            System.arraycopy(messageBytes, tlvIndex, tlvsb, 0, tlvsb.length);
            final OtrInputStream in = new OtrInputStream(tlvsb);
            while (in.available() > 0) {
                tlvs.add(in.readTLV());
            }
        }

        return new Content(message, tlvs);
    }

    /**
     * Content is an inner class that is used to return both message body and accompanying TLVs.
     */
    public static final class Content {
        /**
         * The plaintext (user) message content.
         */
        public final String message;
        /**
         * The TLVs embedded in the Data message.
         */
        public final List<TLV> tlvs;

        private Content(@Nonnull final String message, @Nonnull final List<TLV> tlvs) {
            this.message = requireNonNull(message);
            this.tlvs = requireNonNull(tlvs);
        }
    }
}
