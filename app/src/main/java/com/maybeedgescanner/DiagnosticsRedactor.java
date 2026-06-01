package com.maybeedgescanner;

final class DiagnosticsRedactor {
    private DiagnosticsRedactor() {}

    static String redact(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        String redacted = input;
        redacted = redacted.replaceAll("(?i)(public\\s*ip\\s*:[^\\n]*)", "Public IP: [REDACTED]");
        redacted = redacted.replaceAll("(?i)(local\\s*ip\\s*:[^\\n]*)", "Local IP: [REDACTED]");
        redacted = redacted.replaceAll("(?i)(wan\\s*ip\\s*:[^\\n]*)", "WAN IP: [REDACTED]");
        redacted = redacted.replaceAll("(?i)(token|authorization|cookie)\\s*[:=][^\\n]*", "$1: [REDACTED]");
        redacted = redacted.replaceAll("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "[IPV4_REDACTED]");
        redacted = redacted.replaceAll("(?i)\\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\\b", "[IPV6_REDACTED]");
        return redacted;
    }
}
