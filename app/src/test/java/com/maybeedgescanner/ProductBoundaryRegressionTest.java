package com.maybeedgescanner;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProductBoundaryRegressionTest {
    @Test
    public void maybeEdgeScannerDocsDoNotClaimLockFreeOrArenaPrefix() throws Exception {
        String docs = read("README.md") + "\n"
                + read("docs/USER_GUIDE.md") + "\n"
                + read("docs/ARCHITECTURAL_GUIDE.md") + "\n"
                + read("go-sidecar/README.md");
        String normalized = docs.toLowerCase(Locale.US);

        assertFalse(normalized.contains("lock-free bitwise lookups"));
        assertFalse(normalized.contains("lock-free duplicate filters"));
        assertFalse(normalized.contains("utilize lock-free"));
    }

    @Test
    public void maybeEdgeScannerDocsPreserveRoutePairingContract() throws Exception {
        String readme = read("README.md").toLowerCase(Locale.US);
        String guide = read("docs/USER_GUIDE.md").toLowerCase(Locale.US);

        assertTrue(readme.contains("route-pairing"));
        assertTrue(readme.contains("sni route"));
        assertTrue(readme.contains("opens/observes provider state"));
        assertTrue(guide.contains("sni route-pairing"));
    }

    private static String read(String relativePath) throws IOException {
        return new String(Files.readAllBytes(projectRoot().resolve(relativePath)), StandardCharsets.UTF_8);
    }

    private static Path projectRoot() {
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve("settings.gradle"))) {
            dir = dir.getParent();
        }
        if (dir == null) {
            throw new IllegalStateException("Could not locate MaybeEdgeScanner project root");
        }
        return dir;
    }
}
