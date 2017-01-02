package net.java.otr4j.session;

import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * Class representing OTR Type-Length-Value tuples.
 */
public class TLV {
    /* This is just padding for the encrypted message, and should be ignored. */
    public static final int PADDING=0;
    /* The sender has thrown away his OTR session keys with you */
    public static final int DISCONNECTED=0x0001;

    /* The message contains a step in the Socialist Millionaires' Protocol. */
    // TODO Replace TLV type constants with enum. (Touches public API so might not be good to do right now.)
    public static final int SMP1=0x0002;
    public static final int SMP2=0x0003;
    public static final int SMP3=0x0004;
    public static final int SMP4=0x0005;
    public static final int SMP_ABORT=0x0006;
    /**
     * Like SMP1, but there's a question for the buddy at the beginning.
     */
    public static final int SMP1Q=0x0007;

	private final int type;
	private final byte[] value;

	public TLV(final int type, @Nonnull final byte[] value) {
        this.type = type;
        this.value = Objects.requireNonNull(value);
	}

	public int getType() {
		return type;
	}

	public byte[] getValue() {
		return value;
	}
}