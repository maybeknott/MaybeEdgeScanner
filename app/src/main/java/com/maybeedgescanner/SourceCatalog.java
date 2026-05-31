package com.maybeedgescanner;

import java.util.List;
import java.util.Collection;
import java.util.Set;

final class SourceCatalog {
    static final String DEFAULT_TARGETS = "default_targets.txt";
    static final String DEFAULT_EDGES_EXTRA = "default_edges_extra.txt";
    static final String DEFAULT_SNIS = "default_snis.txt";
    static final String MAYBEPSIPHON_EDGE_IPS = "scan-corpora/maybepsiphon-edge-ips.txt";
    static final String MAYBEPSIPHON_SNI_HOSTS = "scan-corpora/maybepsiphon-sni-hosts.txt";
    static final String COMMUNITY_EDGE_CIDRS_24 = "scan-corpora/community-edge-cidrs-24.txt";
    static final String AKAMAI_AS20940 = "scan-corpora/akamai-AS20940.json";
    static final String AKAMAI_HOSTS_184X = "scan-corpora/akamai-hosts-184x.txt";
    static final String AWS_CLOUDFRONT_RANGES = "scan-corpora/aws-cloudfront-ranges.txt";
    static final String FASTLY_AS54113 = "scan-corpora/fastly-AS54113.json";
    static final String CLOUDFLARE_RANGES = "scan-corpora/cloudflare-ranges.txt";
    static final String GITHUB_PAGES_RANGES = "scan-corpora/github-pages-ranges.txt";
    static final String AZURE_FRONTDOOR_RANGES = "scan-corpora/azure-frontdoor-ranges.txt";
    static final String GOOGLE_CDN_RANGES = "scan-corpora/google-cdn-ranges.txt";
    static final String BUNNY_RANGES = "scan-corpora/bunny-ranges.txt";
    static final String STACKPATH_EDGIO_RANGES = "scan-corpora/stackpath-edgio-ranges.txt";
    static final String OTHER_CLOUD_RANGES = "scan-corpora/other-cloud-ranges.txt";

    private SourceCatalog() {}

    interface Loader {
        List<String> lines(String asset);
        Set<String> tokens(String asset);
        Set<String> communityEdges(String ipAsset, String cidrAsset);
        int estimatedIps(Collection<String> entries);
    }

    static int communityTotal(Loader loader) {
        return loader.estimatedIps(loader.lines(DEFAULT_TARGETS))
                + loader.estimatedIps(loader.lines(DEFAULT_EDGES_EXTRA))
                + loader.estimatedIps(loader.communityEdges(MAYBEPSIPHON_EDGE_IPS, COMMUNITY_EDGE_CIDRS_24));
    }

    static int akamaiTotal(Loader loader) {
        return loader.estimatedIps(loader.tokens(AKAMAI_AS20940))
                + loader.estimatedIps(loader.lines(AKAMAI_HOSTS_184X));
    }

    static int cloudfrontTotal(Loader loader) {
        return loader.estimatedIps(loader.tokens(AWS_CLOUDFRONT_RANGES));
    }

    static int fastlyTotal(Loader loader) {
        return loader.estimatedIps(loader.tokens(FASTLY_AS54113));
    }

    static int cloudflareTotal(Loader loader) {
        return loader.estimatedIps(loader.tokens(CLOUDFLARE_RANGES));
    }

    static int otherNetworkTotal(Loader loader) {
        int total = 0;
        for (String asset : new String[]{
                GITHUB_PAGES_RANGES,
                AZURE_FRONTDOOR_RANGES,
                GOOGLE_CDN_RANGES,
                BUNNY_RANGES,
                STACKPATH_EDGIO_RANGES,
                OTHER_CLOUD_RANGES
        }) {
            total += loader.estimatedIps(loader.tokens(asset));
        }
        return total;
    }
}
