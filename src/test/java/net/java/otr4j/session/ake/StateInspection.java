package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.SharedSecret;

public final class StateInspection {
    
    private StateInspection() {
        // Utility class.
    }
    
    public static SharedSecret extractSharedSecret(final State state) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        if (state instanceof StateAwaitingSig) {
            return (SharedSecret) state.getClass().getField("s").get(state);
        }
        throw new UnsupportedOperationException("Unsupported state.");
    }
}
