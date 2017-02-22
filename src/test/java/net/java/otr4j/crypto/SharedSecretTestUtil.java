package net.java.otr4j.crypto;

import java.security.SecureRandom;

public class SharedSecretTestUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static SharedSecret createTestSecret() {
        return new SharedSecret(OtrCryptoEngine.random(RANDOM, new byte[24]));
    }
}
