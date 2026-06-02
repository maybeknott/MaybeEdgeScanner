package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ResultFilterEngineTest {
    @Test
    public void providerPresetMatchesEdgeRouteClassifications() {
        assertTrue(ResultFilterEngine.providerMatches("Windscribe", "Windscribe WireGuard"));
        assertTrue(ResultFilterEngine.providerMatches("Psiphon", "Psiphon local proxy"));
        assertTrue(ResultFilterEngine.providerMatches("Proxy", "HTTP CONNECT proxy"));
        assertFalse(ResultFilterEngine.providerMatches("Windscribe", "Cloudflare"));
    }

    @Test
    public void hostFilterAcceptsSniHintOrCertificateEvidence() {
        ResultFilterEngine.Spec spec = new ResultFilterEngine.Spec();
        spec.hostText = "front.example";

        List<Row> filtered = ResultFilterEngine.apply(Arrays.asList(
                new Row("host-hint", true, true, true, "TLS 1.3", 40, 95, "Psiphon local proxy", "SAN=edge.example", "front.example", "1.1.1.1:443"),
                new Row("cert-evidence", true, true, false, "TLS 1.3", 50, 90, "Windscribe WireGuard", "SAN=front.example", "edge.example", "2.2.2.2:443"),
                new Row("miss", true, true, true, "TLS 1.3", 20, 99, "Cloudflare", "SAN=other.example", "other.example", "3.3.3.3:443")
        ), spec, Row.ACCESSOR);

        assertEquals(2, filtered.size());
        assertEquals("cert-evidence", filtered.get(0).id);
        assertEquals("host-hint", filtered.get(1).id);
    }

    @Test
    public void routeHostSortIsCaseInsensitive() {
        ResultFilterEngine.Spec spec = new ResultFilterEngine.Spec();
        spec.sortMode = 4;

        List<Row> filtered = ResultFilterEngine.apply(Arrays.asList(
                new Row("beta", true, true, true, "TLS 1.3", 20, 90, "Proxy", "SAN=beta.example", "Beta.example", "1.1.1.1:443"),
                new Row("alpha", true, true, true, "TLS 1.3", 20, 90, "Proxy", "SAN=alpha.example", "alpha.example", "2.2.2.2:443")
        ), spec, Row.ACCESSOR);

        assertEquals("alpha", filtered.get(0).id);
        assertEquals("beta", filtered.get(1).id);
    }

    private static final class Row {
        static final ResultFilterEngine.Accessor<Row> ACCESSOR = new ResultFilterEngine.Accessor<Row>() {
            @Override public boolean working(Row row) { return row.working; }
            @Override public boolean tlsPass(Row row) { return row.tls; }
            @Override public boolean httpPass(Row row) { return row.http; }
            @Override public String tlsVersion(Row row) { return row.tlsVersion; }
            @Override public long totalLatency(Row row) { return row.latency; }
            @Override public double quality(Row row) { return row.quality; }
            @Override public String networkClassification(Row row) { return row.network; }
            @Override public String certificateText(Row row) { return row.cert; }
            @Override public String hostHintText(Row row) { return row.host; }
            @Override public String endpointKey(Row row) { return row.endpoint; }
            @Override public String sortHostKey(Row row) { return row.host; }
        };

        final String id;
        final boolean working;
        final boolean tls;
        final boolean http;
        final String tlsVersion;
        final long latency;
        final double quality;
        final String network;
        final String cert;
        final String host;
        final String endpoint;

        Row(String id, boolean working, boolean tls, boolean http, String tlsVersion,
            long latency, double quality, String network, String cert, String host, String endpoint) {
            this.id = id;
            this.working = working;
            this.tls = tls;
            this.http = http;
            this.tlsVersion = tlsVersion;
            this.latency = latency;
            this.quality = quality;
            this.network = network;
            this.cert = cert;
            this.host = host;
            this.endpoint = endpoint;
        }
    }
}
