/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import org.junit.Test;

import java.util.Date;

import static net.java.otr4j.messages.Validators.validateAtMost;
import static net.java.otr4j.messages.Validators.validateDateAfter;
import static net.java.otr4j.messages.Validators.validateEquals;
import static net.java.otr4j.messages.Validators.validateExactly;

@SuppressWarnings("ConstantConditions")
public final class ValidatorsTest {

    @Test
    public void testValidateEqualsNull() throws ValidationException {
        validateEquals(null, null, "Not good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateEqualsOneNull() throws ValidationException {
        validateEquals(null, new Object(), "Not good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateEqualsOneNull2() throws ValidationException {
        validateEquals(new Object(), null, "Not good");
    }

    @Test
    public void testValidateEqualsEqualObjects() throws ValidationException {
        final Object o = new Object();
        validateEquals(o, o, "Not good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateEqualsDifferentObjects() throws ValidationException {
        validateEquals(new Object(), new Object(), "Good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateExactlyBadValue() throws ValidationException {
        validateExactly(1, 2, "Good");
    }

    @Test
    public void testValidateExactlyCorrectValue() throws ValidationException {
        validateExactly(2, 2, "Good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateAtMostTooMuch() throws ValidationException {
        validateAtMost(10, 11, "Good");
    }

    @Test
    public void testValidateAtMostExactly() throws ValidationException {
        validateAtMost(10, 10, "Not good");
    }

    @Test
    public void testValidateAtMostBelow() throws ValidationException {
        validateAtMost(10, 9, "Not good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateDateExactly() throws ValidationException {
        final Date now = new Date();
        validateDateAfter(now, now, "Good");
    }

    @Test
    public void testValidateDateAfter() throws ValidationException {
        final Date now = new Date();
        final Date after = new Date(Long.MAX_VALUE);
        validateDateAfter(now, after, "Good");
    }

    @Test(expected = ValidationException.class)
    public void testValidateDateBefore() throws ValidationException {
        final Date now = new Date();
        final Date before = new Date(Long.MIN_VALUE);
        validateDateAfter(now, before, "Not good");
    }
}