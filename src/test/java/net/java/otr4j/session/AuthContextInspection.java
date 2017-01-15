package net.java.otr4j.session;

import net.java.otr4j.session.ake.State;

public final class AuthContextInspection {

    private AuthContextInspection() {
        // Utility class.
    }

    public static State extractState(final AuthContext context) {
        return context.getState();
    }
}
