/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;
import java.util.EnumSet;
import java.util.Set;

/**
 * Utilities for OtrPolicy.
 *
 * @author Danny van Heumen
 */
public final class OtrPolicys {

    private OtrPolicys() {
        // utility class, should not be instantiated
    }

    /**
     * Determine list of allowed OTR versions based on the provided OTR policy.
     *
     * @param policy The active OTR policy.
     * @return Returns list of allowed OTR versions.
     */
    @Nonnull
    public static Set<Version> allowedVersions(final OtrPolicy policy) {
        final EnumSet<Version> versions = EnumSet.noneOf(Version.class);
        if (policy.isAllowV2()) {
            versions.add(Version.TWO);
        }
        if (policy.isAllowV3()) {
            versions.add(Version.THREE);
        }
        if (policy.isAllowV4()) {
            versions.add(Version.FOUR);
        }
        return versions;
    }
}
