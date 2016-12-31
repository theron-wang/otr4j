/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

/**
 * @author George Politis
 */
// TODO OtrPolicy currently does not protect the user from configuring a non-viable policy (i.e. disallow all supported OTR versions). This may lead to RuntimeExceptions in the future when this policy is used. (For example, AuthContext#startAuth needs at least one OTR version.)
// TODO consider some intelligence that automatically disables "whitespace tags" if no viable OTR version is allowed in the policy.
public class OtrPolicy {

    /**
     * Flag for indicating otr V1 is allowed in this policy.
     *
     * @deprecated OTR v1 is no longer supported.
     */
    @Deprecated
    public static final int ALLOW_V1 = 0x01;

    public static final int ALLOW_V2 = 0x02;
    // ALLOW_V3 is set to 0x40 for compatibility with older versions
    public static final int ALLOW_V3 = 0x40;
    public static final int REQUIRE_ENCRYPTION = 0x04;
    public static final int SEND_WHITESPACE_TAG = 0x8;
    public static final int WHITESPACE_START_AKE = 0x10;
    public static final int ERROR_START_AKE = 0x20;
    public static final int VERSION_MASK = (ALLOW_V2 | ALLOW_V3);

    // The four old version 1 policies correspond to the following combinations
    // of flags (adding an allowance for version 2 of the protocol):

    public static final int NEVER = 0x00;
    public static final int OPPORTUNISTIC = (ALLOW_V2 | ALLOW_V3
            | SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_MANUAL = (ALLOW_V2 | ALLOW_V3);
    public static final int OTRL_POLICY_ALWAYS = (ALLOW_V2 | ALLOW_V3
            | REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;

    public OtrPolicy() {
        this(NEVER);
    }

    public OtrPolicy(final int policy) {
        this.policy = policy;
    }

    private int policy;

    public int getPolicy() {
        return policy;
    }

    /**
     * getAllowV1 is deprecated as OTR V1 is not supported anymore.
     *
     * @return Always returns false.
     * @deprecated OTR V1 is not supported anymore.
     */
    @Deprecated
    public boolean getAllowV1() {
        return false;
    }

    public boolean getAllowV2() {
        return (policy & OtrPolicy.ALLOW_V2) != 0;
    }

    public boolean getAllowV3() {
        return (policy & OtrPolicy.ALLOW_V3) != 0;
    }

    public boolean getErrorStartAKE() {
        return (policy & OtrPolicy.ERROR_START_AKE) != 0;
    }

    public boolean getRequireEncryption() {
        return getEnableManual()
                && (policy & OtrPolicy.REQUIRE_ENCRYPTION) != 0;
    }

    public boolean getSendWhitespaceTag() {
        return (policy & OtrPolicy.SEND_WHITESPACE_TAG) != 0;
    }

    public boolean getWhitespaceStartAKE() {
        return (policy & OtrPolicy.WHITESPACE_START_AKE) != 0;
    }

    /**
     * OTR V1 is not supported anymore. Calling this method will not change the
     * policy.
     *
     * @param value
     * @deprecated Support for OTR V1 is dropped.
     */
    @Deprecated
    public void setAllowV1(final boolean value) {
    }

    public void setAllowV2(final boolean value) {
        if (value) {
            policy |= ALLOW_V2;
        } else {
            policy &= ~ALLOW_V2;
        }
    }

    public void setAllowV3(final boolean value) {
        if (value) {
            policy |= ALLOW_V3;
        } else {
            policy &= ~ALLOW_V3;
        }
    }

    public void setErrorStartAKE(final boolean value) {
        if (value) {
            policy |= ERROR_START_AKE;
        } else {
            policy &= ~ERROR_START_AKE;
        }
    }

    public void setRequireEncryption(final boolean value) {
        if (value) {
            policy |= REQUIRE_ENCRYPTION;
        } else {
            policy &= ~REQUIRE_ENCRYPTION;
        }
    }

    public void setSendWhitespaceTag(final boolean value) {
        if (value) {
            policy |= SEND_WHITESPACE_TAG;
        } else {
            policy &= ~SEND_WHITESPACE_TAG;
        }
    }

    public void setWhitespaceStartAKE(final boolean value) {
        if (value) {
            policy |= WHITESPACE_START_AKE;
        } else {
            policy &= ~WHITESPACE_START_AKE;
        }
    }

    public boolean getEnableAlways() {
        return getEnableManual() && getErrorStartAKE()
                && getSendWhitespaceTag() && getWhitespaceStartAKE();
    }

    public void setEnableAlways(final boolean value) {
        if (value) {
            setEnableManual(true);
        }

        setErrorStartAKE(value);
        setSendWhitespaceTag(value);
        setWhitespaceStartAKE(value);

    }

    public boolean getEnableManual() {
        return getAllowV2() && getAllowV3();
    }

    public void setEnableManual(final boolean value) {
        setAllowV2(value);
        setAllowV3(value);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != this.getClass()) {
            return false;
        }

        OtrPolicy policy = (OtrPolicy) obj;

        return policy.policy == this.policy;
    }

    @Override
    public int hashCode() {
        return this.policy;
    }
}
