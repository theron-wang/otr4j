package net.java.otr4j.session;

import net.java.otr4j.session.ake.AuthState;

public final class AuthContextInspection {

    private AuthContextInspection() {
        // Utility class.
    }

    public static AuthState extractState(final AuthContext context) {
        return context.getState();
    }
}
