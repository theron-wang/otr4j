package net.java.otr4j.session.ake;

import javax.annotation.Nonnull;

public final class AKEException extends Exception {

    private static final long serialVersionUID = 886730337451533010L;

    public AKEException(@Nonnull final Throwable cause) {
        super(cause);
    }
}
