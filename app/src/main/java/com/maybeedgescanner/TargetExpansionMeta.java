package com.maybeedgescanner;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** CIDR/range expansion context carried alongside staged scan targets. */
final class TargetExpansionMeta implements Serializable {
    private static final long serialVersionUID = 1L;

    final String parentToken;
    final int index;
    final int totalTheoretical;
    final int totalCapped;
    final int skippedCount;
    final String samplingSeed;

    TargetExpansionMeta(String parentToken, int index, int totalTheoretical, int totalCapped, int skippedCount, String samplingSeed) {
        this.parentToken = parentToken == null ? "" : parentToken.trim();
        this.index = index;
        this.totalTheoretical = Math.max(0, totalTheoretical);
        this.totalCapped = Math.max(0, totalCapped);
        this.skippedCount = Math.max(0, skippedCount);
        this.samplingSeed = samplingSeed == null ? "" : samplingSeed.trim();
    }

    boolean hasExpansion() {
        return !parentToken.isEmpty() && index >= 0;
    }

    static TargetExpansionMeta forExpandedMember(String parentToken, int index, int totalTheoretical, int totalCapped) {
        int capped = Math.max(0, totalCapped);
        int theoretical = Math.max(0, totalTheoretical);
        int skipped = Math.max(0, theoretical - capped);
        return new TargetExpansionMeta(parentToken, index, theoretical, capped, skipped, stableSeed(parentToken, capped));
    }

    private static String stableSeed(String parentToken, int capped) {
        String seed = parentToken + "|cap=" + capped;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(seed.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder("seed-");
            for (int i = 0; i < 4; i++) {
                hex.append(String.format(Locale.US, "%02x", hash[i]));
            }
            return hex.toString();
        } catch (Exception ignored) {
            return "seed-" + Math.abs(seed.hashCode());
        }
    }
}
