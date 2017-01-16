package net.java.otr4j.crypto;

import net.java.otr4j.OtrException;

public final class OtrCryptoException extends OtrException {

    private static final long serialVersionUID = -2636945817636034632L;

    public OtrCryptoException(final String message) {
        super(message);
    }

    public OtrCryptoException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public OtrCryptoException(final Throwable e) {
        super(e);
    }
}
