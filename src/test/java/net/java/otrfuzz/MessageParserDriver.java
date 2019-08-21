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
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeNoException;

@RunWith(JQF.class)
public class MessageParserDriver {

    @Fuzz
    public void fuzzMessage(final InputStream input) throws IOException {
        final byte[] data = new byte[4096];
        final int count = input.read(data);
        try {
            assertNotNull(parseMessage(new String(data, 0, count, UTF_8)));
        } catch (final ProtocolException e) {
            assumeNoException(e);
        }
    }
}
