/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otrfuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.messages.ValidationException;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;

import static java.util.Arrays.copyOf;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeNoException;

@RunWith(JQF.class)
public class EncodedMessageParserDriver {

    private final byte[] data = new byte[65536];

    @Fuzz
    public void fuzzMessage(final InputStream input) throws IOException, OtrCryptoException, ValidationException {
        final int length = input.read(this.data);
        final OtrInputStream otrinput = new OtrInputStream(copyOf(this.data, length));
        final int version = otrinput.readShort();
        final byte type = otrinput.readByte();
        final InstanceTag senderTag = otrinput.readInstanceTag();
        final InstanceTag receiverTag = otrinput.readInstanceTag();
        try {
            final EncodedMessage message = new EncodedMessage(version, type, senderTag, receiverTag, otrinput);
            assertNotNull(parseEncodedMessage(message));
        } catch (final ProtocolException | OtrInputStream.UnsupportedLengthException | AssertionError e) {
            assumeNoException(e);
        } catch (final IllegalStateException e) {
            if (e.getMessage().startsWith("BUG: Unexpected protocol version found.")) {
                assumeNoException(e);
            }
            throw e;
        } catch (final UnsupportedOperationException e) {
            if (e.getMessage().startsWith("BUG: Future protocol versions are not supported.")
                    || e.getMessage().equals("Illegal protocol version: version 1 is no longer supported.")) {
                assumeNoException(e);
            }
            throw e;
        }
    }
}
