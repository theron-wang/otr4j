/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
package net.java.otr4j.api;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests for OtrPolicyUtil.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class OtrPolicysTest {

    public OtrPolicysTest() {
    }

    @Test(expected = NullPointerException.class)
    public void testAllowedVersionsNullPolicy() {
        OtrPolicys.allowedVersions(null);
    }

    @Test
    public void testAllowedVersionsDefaultPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OTRL_POLICY_DEFAULT);
        final Set<Version> versions = OtrPolicys.allowedVersions(policy);
        assertEquals(3, versions.size());
        assertTrue(versions.contains(Version.TWO));
        assertTrue(versions.contains(Version.THREE));
        assertTrue(versions.contains(Version.FOUR));
    }

    @Test
    public void testAllowedVersionsNoVersionPolicy() {
        final OtrPolicy policy = new OtrPolicy(0);
        final Set<Version> versions = OtrPolicys.allowedVersions(policy);
        assertEquals(0, versions.size());
    }

    @Test
    public void testAllowedVersionsMinimalPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        final Set<Version> versions = OtrPolicys.allowedVersions(policy);
        assertEquals(1, versions.size());
        assertTrue(versions.contains(Version.THREE));
    }

    @Test
    public void testAllowedVersionsCustomPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3 | OtrPolicy.WHITESPACE_START_AKE);
        final Set<Version> versions = OtrPolicys.allowedVersions(policy);
        assertEquals(2, versions.size());
        assertTrue(versions.contains(Version.TWO));
        assertTrue(versions.contains(Version.THREE));
    }
}
