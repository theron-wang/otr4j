package net.java.otr4j.io;

import java.io.IOException;
import java.util.Arrays;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.Session;
import net.java.otr4j.session.Session.OTRv;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class SerializationUtilsTest {

	@Test
	public void testOTRQueryMessageV1NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV2NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTRv2? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV23NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTRv23? some other content ..."));
	}
	
	@Test
	public void testCorrectOTREncodingDetection() {
		assertTrue(SerializationUtils.otrEncoded("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==."));
	}

	@Test
	public void testOTRv2FragmentNotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test
	public void testOTRv3FragmentNotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test(expected = IOException.class)
	public void testToMessageWrongProtocolVersion() throws Exception {
		SerializationUtils
				.toMessage("?OTR:AAQDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
	}

    @Test
    public void testByteArrayToHexStringNullArray() {
        assertNull(SerializationUtils.byteArrayToHexString(null));
    }

    @Test
    public void testByteArrayToHexStringEmptyArray() {
        assertNull(SerializationUtils.byteArrayToHexString(new byte[0]));
    }

    @Test
    public void testByteArrayToHexStringSmallArray() {
        assertEquals("616230212F", SerializationUtils.byteArrayToHexString(new byte[] { 'a', 'b', '0', '!', '/'}));
    }

    @Test
    public void testByteArrayToHexStringAndBack() {
        final byte[] line = "This is a line of text for testing out methods used for byte array to hex string conversions.".getBytes(SerializationUtils.UTF8);
        assertArrayEquals(line, SerializationUtils.hexStringToByteArray(SerializationUtils.byteArrayToHexString(line)));
    }

    @Test
    public void testPlaintextMessageNoNullMangling() throws IOException {
        final String data = "This is a test with \0 null \0 values.";
        final PlainTextMessage m = new PlainTextMessage(Arrays.asList(OTRv.TWO, OTRv.THREE), data);
        assertTrue(SerializationUtils.toString(m).startsWith("This is a test with \0 null \0 values."));
    }

    @Test
    public void testBytesConversionNullMangling() {
        assertArrayEquals("This is a test with ? null ? values.".getBytes(SerializationUtils.UTF8),
                SerializationUtils.convertTextToBytes("This is a test with \0 null \0 values."));
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t ");
        assertTrue(msg.versions.isEmpty());
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t ");
        assertEquals(1, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.TWO));
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV3() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t\t");
        assertEquals(1, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.THREE));
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2AndV3() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t");
        assertEquals(2, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.TWO));
        assertTrue(msg.versions.contains(Session.OTRv.THREE));
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV2() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t ");
        assertEquals(1, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.TWO));
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV3() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t");
        assertEquals(1, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.THREE));
        assertEquals("", msg.cleanText);
    }

    @Test
    public void testCorrectWhitespaceErasure() throws IOException, OtrCryptoException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage("Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t world!");
        assertEquals(1, msg.versions.size());
        assertTrue(msg.versions.contains(Session.OTRv.THREE));
        assertEquals("Hello world!", msg.cleanText);
    }
}
