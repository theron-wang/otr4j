package net.java.otr4j.crypto;

import java.security.SecureRandom;

public class SharedSecretTestUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static SharedSecret createTestSecret() {
        // TODO does size of shared secret make sense? (representative?)
        return new SharedSecret(OtrCryptoEngine.random(RANDOM, new byte[24]));
    }
}
