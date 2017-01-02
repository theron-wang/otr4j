package net.java.otr4j;

import org.junit.Test;
import static org.junit.Assert.*;

public class OtrPolicyTest {

    @Test
    public void testViablePolicyOTRv2Andv3() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3 | OtrPolicy.WHITESPACE_START_AKE);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyOTRv2Only() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyOTRv3Only() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyNone() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.WHITESPACE_START_AKE | OtrPolicy.SEND_WHITESPACE_TAG);
        assertFalse(policy.viable());
    }

    @Test
    public void testViablePolicyOpportunistic() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        assertTrue(policy.viable());
    }

    @Test
    public void testV1NeverAllowed() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V1);
        assertFalse(policy.getAllowV1());
    }

    @Test
    public void testAllowV2Policy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2);
        assertTrue(policy.getAllowV2());
    }

    @Test
    public void testAllowV3Policy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertTrue(policy.getAllowV3());
    }

    @Test
    public void testConditionalStartAKEAfterErrorPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.getErrorStartAKE());
        policy.setErrorStartAKE(true);
        assertTrue(policy.getErrorStartAKE());
        policy.setAllowV3(false);
        assertFalse(policy.getErrorStartAKE());
    }

    @Test
    public void testConditionalSendWhitespacePolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.getSendWhitespaceTag());
        policy.setSendWhitespaceTag(true);
        assertTrue(policy.getSendWhitespaceTag());
        policy.setAllowV3(false);
        assertFalse(policy.getSendWhitespaceTag());
    }

    @Test
    public void testConditionalWhitespaceStartAKEPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.getWhitespaceStartAKE());
        policy.setWhitespaceStartAKE(true);
        assertTrue(policy.getWhitespaceStartAKE());
        policy.setAllowV3(false);
        assertFalse(policy.getWhitespaceStartAKE());
    }

    @Test
    public void testRequireEncryptionWithAllowedProtocols() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OTRL_POLICY_ALWAYS);
        policy.setAllowV2(false);
        policy.setAllowV3(false);
        assertTrue(policy.getRequireEncryption());
    }
    
    @Test
    public void testSetEnableAlways() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.NEVER);
        assertFalse(policy.getAllowV2());
        assertFalse(policy.getAllowV3());
        assertFalse(policy.getRequireEncryption());
        assertFalse(policy.getWhitespaceStartAKE());
        assertFalse(policy.getErrorStartAKE());
        assertFalse(policy.getEnableAlways());
        policy.setEnableAlways(true);
        assertTrue(policy.getAllowV2());
        assertTrue(policy.getAllowV3());
        assertTrue(policy.getRequireEncryption());
        assertTrue(policy.getWhitespaceStartAKE());
        assertTrue(policy.getErrorStartAKE());
        assertTrue(policy.getEnableAlways());
    }
}
