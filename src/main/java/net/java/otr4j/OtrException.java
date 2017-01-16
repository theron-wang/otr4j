package net.java.otr4j;

public class OtrException extends Exception {

    private static final long serialVersionUID = -6327624437614707245L;

    public OtrException(final Throwable e) {
        super(e);
    }

    public OtrException(final String message) {
        super(message);
    }

    public OtrException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
