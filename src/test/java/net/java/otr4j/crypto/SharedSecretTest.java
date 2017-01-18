package net.java.otr4j.crypto;

import org.junit.Test;

public class SharedSecretTest {

    public SharedSecretTest() {
    }

    @Test(expected = NullPointerException.class)
    public void testNullSecret() {
        new SharedSecret(null);
    }

    @Test
    public void testEmptySecret() {
        new SharedSecret(new byte[0]);
    }
}
