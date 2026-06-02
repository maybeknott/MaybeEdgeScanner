package com.maybeedgescanner;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

final class ScanTargetPlanner {
    private ScanTargetPlanner() {}

    static String scanLimitLabel(int targetCap) {
        return targetCap <= 0 ? "unlimited" : String.format(java.util.Locale.US, "%,d", targetCap);
    }

    static int effectiveScanCap(int targetCap, int estimatedTargets) {
        if (targetCap <= 0) return Math.max(0, estimatedTargets);
        return Math.min(Math.max(0, estimatedTargets), targetCap);
    }

    static List<String> lines(String value) {
        return unique(Arrays.asList(String.valueOf(value == null ? "" : value).split("[,;\\s\\r\\n]+")));
    }

    static List<String> unique(Collection<String> values) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null || value.trim().isEmpty()) continue;
            String clean = cleanToken(value);
            if (!clean.isEmpty()) out.add(clean);
        }
        return new ArrayList<>(out);
    }

    static List<Integer> parsePorts(String value) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        for (String part : String.valueOf(value == null ? "" : value).split("[,;\\s]+")) {
            try {
                int port = Integer.parseInt(part.trim());
                if (port > 0 && port < 65536) ports.add(port);
            } catch (Exception ignored) {
            }
        }
        if (ports.isEmpty()) ports.add(443);
        return new ArrayList<>(ports);
    }

    static boolean isIpv4(String value) {
        if (value == null) return false;
        String clean = value.trim();
        if (!clean.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return false;
        String[] parts = clean.split("\\.");
        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) return false;
            } catch (Exception ignored) {
                return false;
            }
        }
        return true;
    }

    static boolean isIp(String value) {
        if (value == null) return false;
        String clean = value.trim();
        if (isIpv4(clean)) return true;
        if (!clean.contains(":") || !clean.matches("(?i)[0-9a-f:.]+")) return false;
        try {
            return InetAddress.getByName(clean) instanceof Inet6Address;
        } catch (Exception ignored) {
            return false;
        }
    }

    static boolean looksLikePrefix(String value) {
        return value != null && value.trim().contains("/");
    }

    static boolean looksLikeIpv4Range(String value) {
        if (value == null) return false;
        String[] parts = value.trim().split("-", 2);
        return parts.length == 2 && isIpv4(parts[0]) && isIpv4(parts[1]);
    }

    static List<String> expandTargets(List<String> raw, int totalCap) {
        ArrayList<String> out = new ArrayList<>();
        for (ExpandedTarget entry : expandTargetsDetailed(raw, totalCap)) {
            out.add(entry.address);
        }
        return out;
    }

    static final class ExpandedTarget {
        final String address;
        final TargetExpansionMeta expansion;

        ExpandedTarget(String address, TargetExpansionMeta expansion) {
            this.address = address == null ? "" : address.trim();
            this.expansion = expansion;
        }
    }

    static List<ExpandedTarget> expandTargetsDetailed(List<String> raw, int totalCap) {
        ArrayList<ExpandedTarget> out = new ArrayList<>();
        int cap = totalCap <= 0 ? Integer.MAX_VALUE : totalCap;
        for (String value : raw) {
            if (out.size() >= cap) break;
            String clean = cleanToken(value);
            if (clean.isEmpty()) continue;
            int remaining = cap - out.size();
            if (looksLikePrefix(clean)) {
                appendExpanded(out, clean, expandCidr(clean, remaining), estimateCidrCount(clean, Integer.MAX_VALUE));
            } else if (looksLikeIpv4Range(clean)) {
                appendExpanded(out, clean, expandRange(clean, remaining), estimateRangeCount(clean, Integer.MAX_VALUE));
            } else {
                out.add(new ExpandedTarget(clean, null));
            }
        }
        return out;
    }

    private static void appendExpanded(ArrayList<ExpandedTarget> out, String parent, List<String> members, int theoretical) {
        int capped = members.size();
        for (int i = 0; i < members.size(); i++) {
            out.add(new ExpandedTarget(members.get(i), TargetExpansionMeta.forExpandedMember(parent, i, theoretical, capped)));
        }
    }

    static List<String> expandTargets(List<String> raw) {
        return expandTargets(raw, Integer.MAX_VALUE);
    }

    static int estimateExpandedTargetCount(Collection<String> raw, int perEntryCap) {
        long total = 0;
        for (String value : raw) {
            String clean = cleanToken(value);
            if (clean.isEmpty()) continue;
            if (looksLikePrefix(clean)) total += estimateCidrCount(clean, perEntryCap);
            else if (looksLikeIpv4Range(clean)) total += estimateRangeCount(clean, perEntryCap);
            else total++;
            if (total > Integer.MAX_VALUE) return Integer.MAX_VALUE;
        }
        return (int) total;
    }

    static int estimateCidrCount(String cidr, int cap) {
        try {
            String[] parts = cidr.split("/", 2);
            if (parts.length != 2 || !isIp(parts[0]) || cap <= 0) return 0;
            int prefix = Integer.parseInt(parts[1]);
            if (parts[0].contains(":")) {
                if (prefix < 0 || prefix > 128) return 0;
                return cap;
            }
            if (prefix < 0 || prefix > 32) return 0;
            long size = 1L << (32 - prefix);
            long usable = size > 2 ? size - 2 : size;
            return (int) Math.min(Math.max(0, usable), cap);
        } catch (Exception ignored) {
            return 0;
        }
    }

    static int estimateRangeCount(String range, int cap) {
        try {
            String[] parts = range.split("-", 2);
            if (parts.length != 2 || !isIpv4(parts[0]) || !isIpv4(parts[1]) || cap <= 0) return 0;
            long start = ipv4ToLong(parts[0]);
            long end = ipv4ToLong(parts[1]);
            if (end < start) return 0;
            return (int) Math.min(end - start + 1, cap);
        } catch (Exception ignored) {
            return 0;
        }
    }

    static List<String> resolve(String target) {
        try {
            if (isIp(target)) return Collections.singletonList(target);
            InetAddress[] addresses = InetAddress.getAllByName(target);
            List<String> out = new ArrayList<>();
            for (InetAddress address : addresses) if (address instanceof Inet6Address) out.add(address.getHostAddress());
            for (InetAddress address : addresses) if (!(address instanceof Inet6Address)) out.add(address.getHostAddress());
            return unique(out);
        } catch (Exception ignored) {
            return Collections.emptyList();
        }
    }

    static String cleanToken(String value) {
        return String.valueOf(value == null ? "" : value)
                .trim()
                .replace("\"", "")
                .replace(",", "")
                .replace("[", "")
                .replace("]", "");
    }

    private static List<String> expandRange(String range, int cap) {
        List<String> out = new ArrayList<>();
        try {
            String[] parts = range.split("-", 2);
            if (parts.length != 2 || !isIpv4(parts[0]) || !isIpv4(parts[1]) || cap <= 0) return out;
            long start = ipv4ToLong(parts[0]);
            long end = ipv4ToLong(parts[1]);
            if (end < start) return out;
            for (long value = start; value <= end && out.size() < cap; value++) out.add(longToIpv4(value));
        } catch (Exception ignored) {
        }
        return out;
    }

    private static List<String> expandCidr(String cidr, int cap) {
        List<String> out = new ArrayList<>();
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2 || !isIp(parts[0])) return out;
            if (parts[0].contains(":")) return expandIpv6Cidr(parts[0], Integer.parseInt(parts[1]), cap);
            long ip = ipv4ToLong(parts[0]);
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > 32) return out;
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            long start = ip & mask;
            long end = start | (~mask & 0xffffffffL);
            long first = end - start + 1 <= 2 ? start : start + 1;
            long last = end - start + 1 <= 2 ? end : end - 1;
            for (long value = first; value <= last && out.size() < cap; value++) out.add(longToIpv4(value));
        } catch (Exception ignored) {
        }
        return out;
    }

    private static List<String> expandIpv6Cidr(String ipText, int prefix, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (prefix < 0 || prefix > 128 || cap <= 0) return out;
            byte[] bytes = InetAddress.getByName(ipText).getAddress();
            BigInteger ip = new BigInteger(1, bytes);
            BigInteger all = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
            BigInteger mask = prefix == 0 ? BigInteger.ZERO : all.shiftRight(128 - prefix).shiftLeft(128 - prefix);
            BigInteger start = ip.and(mask);
            BigInteger size = BigInteger.ONE.shiftLeft(128 - prefix);
            BigInteger current = start;
            if (size.compareTo(BigInteger.ONE) > 0) current = current.add(BigInteger.ONE);
            for (int i = 0; i < cap && current.subtract(start).compareTo(size) < 0; i++) {
                out.add(bigToIpv6(current));
                current = current.add(BigInteger.ONE);
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private static String bigToIpv6(BigInteger value) throws Exception {
        byte[] raw = value.toByteArray();
        byte[] bytes = new byte[16];
        int src = Math.max(0, raw.length - 16);
        int len = Math.min(16, raw.length);
        System.arraycopy(raw, src, bytes, 16 - len, len);
        return InetAddress.getByAddress(bytes).getHostAddress();
    }

    private static long ipv4ToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (String part : parts) result = (result << 8) | Integer.parseInt(part);
        return result & 0xffffffffL;
    }

    private static String longToIpv4(long value) {
        return ((value >> 24) & 255) + "." + ((value >> 16) & 255) + "." + ((value >> 8) & 255) + "." + (value & 255);
    }

    /** Distinct TargetPlan v1 plan_id count for a capped preview sample (E2 preview correlation). */
    static int countDistinctPreviewPlans(Collection<String> previewTargets, int port, boolean sniPairingEnabled,
                                         EdgeRouteProfile routeProfile, String sniHost) {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        int safePort = port > 0 && port < 65536 ? port : 443;
        String sni = sniHost == null ? "" : sniHost.trim();
        for (String target : previewTargets) {
            if (target == null || target.trim().isEmpty()) continue;
            String token = target.trim();
            String resolvedIp = isIp(token) ? token : "";
            ids.add(TargetPlanRecord.forRoutePairingProbe(token, resolvedIp, safePort, sni, sniPairingEnabled, routeProfile).planId());
        }
        return ids.size();
    }
}
