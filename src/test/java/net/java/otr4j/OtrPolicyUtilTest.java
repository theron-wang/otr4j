/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.List;
import net.java.otr4j.session.Session;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for OtrPolicyUtil.
 *
 * @author Danny van Heumen
 */
public class OtrPolicyUtilTest {

    public OtrPolicyUtilTest() {
    }

    @Test(expected = NullPointerException.class)
    public void testAllowedVersionsNullPolicy() {
        OtrPolicyUtil.allowedVersions(null);
    }

    @Test
    public void testAllowedVersionsDefaultPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OTRL_POLICY_DEFAULT);
        final List<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(3, versions.size());
        assertTrue(versions.contains(Session.OTRv.ONE));
        assertTrue(versions.contains(Session.OTRv.TWO));
        assertTrue(versions.contains(Session.OTRv.THREE));
    }

    @Test
    public void testAllowedVersionsNoVersionPolicy() {
        final OtrPolicy policy = new OtrPolicy(0);
        final List<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(0, versions.size());
    }

    @Test
    public void testAllowedVersionsMinimalPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        final List<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(1, versions.size());
        assertTrue(versions.contains(Session.OTRv.THREE));
    }

    @Test
    public void testAllowedVersionsCustomPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3 | OtrPolicy.WHITESPACE_START_AKE);
        final List<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(2, versions.size());
        assertTrue(versions.contains(Session.OTRv.TWO));
        assertTrue(versions.contains(Session.OTRv.THREE));
    }
}
