package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScanInputAnalyzerTest {
    @Test
    public void targetStatsPreserveRoutePairingExpansionShape() {
        String raw = "8.8.8.8\nedge-route.invalid 8.8.8.8\nbad/host\n8.8.0.0/30\n8.8.8.1-8.8.8.3";

        String stats = ScanInputAnalyzer.customTargetStatsText(
                raw,
                values -> {
                    String value = values.get(0);
                    if (value.contains("/")) return 4;
                    if (ScanTargetPlanner.looksLikeIpv4Range(value)) return 3;
                    return 1;
                },
                (value, cap) -> value.contains("/") ? 4 : 0,
                (value, cap) -> ScanTargetPlanner.looksLikeIpv4Range(value) ? 3 : 0);

        assertTrue(stats.contains("6 items"));
        assertTrue(stats.contains("5 valid"));
        assertTrue(stats.contains("1 invalid"));
        assertTrue(stats.contains("1 duplicates"));
        assertTrue(stats.contains("about 10 IPs"));
        assertTrue(stats.contains("1 hostnames"));
    }

    @Test
    public void customSniStatsTrackRoutePairingCorpusQuality() {
        String stats = ScanInputAnalyzer.customSniStatsText("Edge.Example.com edge.example.com bad_host front.example.net");

        assertTrue(stats.contains("Custom SNI hosts: 4 items"));
        assertTrue(stats.contains("3 valid"));
        assertTrue(stats.contains("1 invalid"));
        assertTrue(stats.contains("1 duplicates"));
        assertTrue(stats.contains("Preview: edge.example.com, front.example.net"));
    }

    @Test
    public void hasValidTargetsRejectsRouteOnlyNoise() {
        assertFalse(ScanInputAnalyzer.hasValidTargets("bad_host"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("1.1.1.1"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("edge.example.com"));
        assertTrue(ScanInputAnalyzer.hasValidTargets("edge-route.example.com"));
    }

    @Test
    public void previewExpandedTargetsSamplesOnlyExpandedForms() {
        List<String> preview = ScanInputAnalyzer.previewExpandedTargets(
                Arrays.asList("8.8.0.0/30", "8.8.8.1-8.8.8.3", "edge.example.com", "edge-route.example.com"),
                4,
                (value, index) -> value + "#" + index);

        assertEquals(Arrays.asList("8.8.0.0/30#0", "8.8.8.1-8.8.8.3#1", "edge.example.com", "edge-route.example.com"), preview);
    }

}
