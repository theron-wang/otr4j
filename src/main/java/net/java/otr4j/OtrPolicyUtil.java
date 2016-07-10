/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.ArrayList;
import java.util.List;
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
    public static List<Integer> allowedVersions(@Nonnull final OtrPolicy policy) {
        final ArrayList<Integer> versions = new ArrayList<Integer>(4);
        if (policy.getAllowV1()) {
            versions.add(Session.OTRv.ONE);
        }
        if (policy.getAllowV2()) {
            versions.add(Session.OTRv.TWO);
        }
        if (policy.getAllowV3()) {
            versions.add(Session.OTRv.THREE);
        }
        return versions;
    }
}
