/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import net.java.otr4j.session.Session;

/**
 * Utilities for OtrPolicy.
 *
 * @author Danny van Heumen
 */
public final class OtrPolicyUtil {

    private OtrPolicyUtil() {
        // utility class, should not be instantiated
    }

    /**
     * Determine list of allowed OTR versions based on the provided OTR policy.
     *
     * @param policy The active OTR policy.
     * @return Returns list of allowed OTR versions.
     */
    @Nonnull
    public static Set<Integer> allowedVersions(@Nonnull final OtrPolicy policy) {
        final HashSet<Integer> versions = new HashSet<Integer>();
        if (policy.getAllowV2()) {
            versions.add(Session.OTRv.TWO);
        }
        if (policy.getAllowV3()) {
            versions.add(Session.OTRv.THREE);
        }
        return versions;
    }
}
