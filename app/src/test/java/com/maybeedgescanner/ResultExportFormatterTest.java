package com.maybeedgescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ResultExportFormatterTest {
    @Test
    public void lineAndCommaExportsDeduplicateIps() throws Exception {
        String lines = ResultExportFormatter.buildNonJsonContent(
                Arrays.asList(result("edge.example", "1.1.1.1", 443, "front.example"), result("dupe.example", "1.1.1.1", 443, "other.example")),
                0,
                Row.ACCESSOR);
        String comma = ResultExportFormatter.buildNonJsonContent(
                Arrays.asList(result("edge.example", "1.1.1.1", 443, "front.example"), result("two.example", "2.2.2.2", 443, "front.example")),
                1,
                Row.ACCESSOR);

        assertEquals("1.1.1.1", lines);
        assertEquals("1.1.1.1,2.2.2.2", comma);
    }

    @Test
    public void routePairAndSniExportsKeepEdgePairingIdentity() throws Exception {
        String pairs = ResultExportFormatter.buildNonJsonContent(
                Collections.singletonList(result("edge.example", "1.1.1.1", 8443, "front.example")),
                2,
                Row.ACCESSOR);
        String snis = ResultExportFormatter.buildNonJsonContent(
                Arrays.asList(result("one.example", "1.1.1.1", 443, "front.example"), result("two.example", "2.2.2.2", 443, "front.example")),
                3,
                Row.ACCESSOR);

        assertEquals("1.1.1.1:8443 front.example", pairs);
        assertEquals("front.example", snis);
    }

    @Test
    public void csvFormatKeepsStructuredResultFields() throws Exception {
        Row row = result("edge.example", "1.1.1.1", 443, "front.example");

        String csv = ResultExportFormatter.buildNonJsonContent(Collections.singletonList(row), 4, Row.ACCESSOR);

        assertTrue(csv.startsWith("target,ip,port,sni,tcp,tls,http"));
        assertTrue(csv.contains("edge.example,1.1.1.1,443"));
    }

    private static Row result(String target, String ip, int port, String sni) {
        return new Row(target, ip, port, sni);
    }

    private static final class Row {
        static final ResultExportFormatter.Accessor<Row> ACCESSOR = new ResultExportFormatter.Accessor<Row>() {
            @Override public String ip(Row row) { return row.ip; }
            @Override public String address(Row row) { return row.ip + ":" + row.port; }
            @Override public String sni(Row row) { return row.sni; }
            @Override public String csv(Row row) {
                return row.target + "," + row.ip + "," + row.port + "," + row.sni + ",true,true,true,200,60,h2,TLS 1.3,,Psiphon local proxy,95,ok";
            }
        };

        final String target;
        final String ip;
        final int port;
        final String sni;

        Row(String target, String ip, int port, String sni) {
            this.target = target;
            this.ip = ip;
            this.port = port;
            this.sni = sni;
        }
    }
}
