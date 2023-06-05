/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * EventExtraSymmetricKey is the event class that carries the data for the corresponding event.
 */
public final class EventExtraSymmetricKey {

    /**
     * The extra symmetric key, base-key in case of OTRv3, or derived key (according to spec) for OTRv4.
     */
    public final byte[] key;
    /**
     * The context (4-byte) value present in the TLV value.
     */
    public final byte[] context;
    /**
     * The remaining bytes present in the TLV value.
     */
    public final byte[] value;

    /**
     * Constructor for the event.
     *
     * @param key the extra symmetric key
     * @param context the context
     * @param value the (remaining) value
     */
    public EventExtraSymmetricKey(final byte[] key, final byte[] context, final byte[] value) {
        this.key = requireNonNull(key);
        this.context = requireLengthExactly(4, context);
        this.value = requireNonNull(value);
    }
}
