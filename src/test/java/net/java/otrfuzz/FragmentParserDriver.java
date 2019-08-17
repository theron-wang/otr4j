package net.java.otrfuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.Fragment.parse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeNoException;

@RunWith(JQF.class)
public class FragmentParserDriver {

    @Fuzz
    public void fuzzFragment(@Nonnull final InputStream input) throws IOException {
        final byte[] data = new byte[4096];
        final int count = input.read(data);
        try {
            assertNotNull(parse(new String(data, 0, count, UTF_8)));
        } catch (final ProtocolException e) {
            assumeNoException(e);
        }
    }
}
