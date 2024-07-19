/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.dake;

import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;

import javax.annotation.Nonnull;
import java.util.logging.Logger;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.INFO;

/**
 * The initial state in the OTRv4 interactive DAKE.
 */
public final class DAKEInitial extends AbstractState implements DAKEState {

    private static final Logger LOGGER = Logger.getLogger(DAKEInitial.class.getName());

    private static final DAKEInitial INSTANCE = new DAKEInitial();

    DAKEInitial() {
        // Note: allowing DAKE states to instantiate `DAKEInitial()` such that transitions back to initial state carry
        // an updated timestamp. This is slightly inefficient, as we could have reused the shared `INSTANCE`.
        super();
    }

    /**
     * Acquire the (singleton) instance of DAKEInitial.
     *
     * @return the instance
     */
    @Nonnull
    public static DAKEInitial instance() {
        return INSTANCE;
    }

    @Nonnull
    @Override
    public Result handle(final DAKEContext context, final AbstractEncodedMessage message) {
        if (!(message instanceof IdentityMessage)) {
            LOGGER.log(FINE, "Ignoring unexpected DAKE message type: " + message.getType());
            return new Result();
        }
        try {
            return handleIdentityMessage(context, (IdentityMessage) message);
        } catch (final ValidationException e) {
            LOGGER.log(INFO, "Failed to process Identity message.", e);
            return new Result();
        }
    }
}
