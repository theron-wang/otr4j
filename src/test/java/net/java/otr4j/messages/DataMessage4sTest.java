package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;

@SuppressWarnings("resource")
public final class DataMessage4sTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testFirstRatchetFirstMessageWithoutRevealsMustBeAccepted() throws ProtocolException {
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 msg = new DataMessage4(InstanceTag.SMALLEST_TAG, InstanceTag.HIGHEST_TAG, (byte) 0, 0, 0, 0, ecdh.publicKey(), dh.publicKey(), new byte[0], new byte[64], new byte[0]);
        DataMessage4s.verify(msg);
    }

    @Test(expected = ProtocolException.class)
    public void testFirstMessageInNextRatchetWithoutReveals() throws ProtocolException {
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DataMessage4 msg = new DataMessage4(InstanceTag.SMALLEST_TAG, InstanceTag.HIGHEST_TAG, (byte) 0, 0, 1, 0, ecdh.publicKey(), null, new byte[0], new byte[64], new byte[0]);
        DataMessage4s.verify(msg);
    }

    @Test
    public void testFirstMessageInNextRatchetWithReveals() throws ProtocolException {
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DataMessage4 msg = new DataMessage4(InstanceTag.SMALLEST_TAG, InstanceTag.HIGHEST_TAG, (byte) 0, 0, 1, 0, ecdh.publicKey(), null, new byte[0], new byte[64], new byte[64]);
        DataMessage4s.verify(msg);
    }
}