/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

/**
 * ValidationException indicates an issue while performing Ed448 elliptic curve operations.
 * <p>
 * Typically these exceptions indicate either issues with the public key (e.g. an illegal point) or a problem with
 * validating a message against its supposed signature.
 */
public final class ValidationException extends Exception {

    private static final long serialVersionUID = 8773101647127876355L;

    ValidationException(final String message) {
        super(message);
    }

    ValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
