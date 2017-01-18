package net.java.otr4j.session.ake;

import javax.annotation.Nonnull;

/**
 * Exception type for signaling exceptions that occur in AKE.
 *
 * @author Danny van Heumen
 */
// FIXME AKEException is now used from outside 'ake' package. Is this really structured correctly?
public final class AKEException extends Exception {

    private static final long serialVersionUID = 886730337451533010L;

    public AKEException(@Nonnull final Throwable cause) {
        super(cause);
    }
}
