package com.phishingdetection.utils;


import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Pattern;

public class HttpUtils {

    private static final List<String> LEGITIMATE_DOMAINS = Arrays.asList("paypal.com", "google.com", "bankofamerica.com");
    private static final List<String> SUSPICIOUS_PATTERNS = Arrays.asList("login", "secure", "verify", "account", "update", "paypal", "bank", "signin", "auth");
    private static final Pattern OBSCURED_URL_PATTERN = Pattern.compile("([a-zA-Z0-9]{3,})\\.[a-zA-Z0-9]{2,}\\.[a-zA-Z0-9]{2,}");

    // Levenshtein distance threshold for domain similarity
    private static final int SIMILARITY_THRESHOLD = 3;
    
    private static List<String> MALICIOUS_DOMAINS = new ArrayList<>();

    static {
        
        loadMaliciousDomains("C:/Users/KREET ROUT/Desktop/Sem 7/J-Component/phishing-detection-tool/PhishingDetectionTool/src/main/java/com/phishingdetection/utils/malicious_domains.txt");
    }

    public static boolean isPhishingUrl(String url) {
        int totalChecks = 7; // Number of checks performed
        int maliciousChecks = 0; // Count of checks that identify the URL as malicious

        // Step 1
        if (isKnownMaliciousDomain(url)) {
            maliciousChecks++;
        }

        // Step 2: Check for suspicious patterns commonly used in phishing
        if (isSuspiciousPattern(url)) {
            maliciousChecks++;
        }

        // Step 3: Check for URL obfuscation
        if (isObfuscatedUrl(url)) {
            maliciousChecks++;
        }

        // Step 4: Check if the domain is suspiciously similar to a legitimate domain
        String domain = extractDomainFromUrl(url);
        if (isDomainSimilarToLegitimate(domain)) {
            maliciousChecks++;
        }

        // Step 5: Check if the URL uses HTTPS
        if (!url.startsWith("https://")) {
            maliciousChecks++;
        }

        // Step 6: Check if there are excessive subdomains
        if (hasExcessiveSubdomains(domain)) {
            maliciousChecks++;
        }

        // Step 7: Check if the domain name is too long (suspiciously long domain names)
        if (isDomainNameTooLong(domain)) {
            maliciousChecks++;
        }

        // Calculate the percentage of malicious checks
        double maliciousPercentage = ((double) maliciousChecks / totalChecks) * 100;
        LoggerUtil.logInfo("Phishing probability for domain '" + domain + "': " + maliciousPercentage + "%");

        if(maliciousPercentage > 20){
            return true;
        }

        return false;
    }

    public static boolean isKnownMaliciousDomain(String url) {
        String domain = extractDomainFromUrl(url);
        return MALICIOUS_DOMAINS.contains(domain);
    }

    public static boolean isSuspiciousPattern(String url) {
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (url.toLowerCase().contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isObfuscatedUrl(String url) {
        return OBSCURED_URL_PATTERN.matcher(url).find();
    }

    

    private static boolean isDomainSimilarToLegitimate(String domain) {
        for (String legitimateDomain : LEGITIMATE_DOMAINS) {
            if (calculateLevenshteinDistance(domain, legitimateDomain) <= SIMILARITY_THRESHOLD) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasExcessiveSubdomains(String domain) {
        String[] subdomains = domain.split("\\.");
        return subdomains.length > 4; // Arbitrary threshold for excessive subdomains
    }

    private static boolean isDomainNameTooLong(String domain) {
        return domain.length() > 30; // Arbitrary length threshold for suspiciously long domains
    }

    private static int calculateLevenshteinDistance(String str1, String str2) {
        int lenStr1 = str1.length();
        int lenStr2 = str2.length();
        int[][] dp = new int[lenStr1 + 1][lenStr2 + 1];

        for (int i = 0; i <= lenStr1; i++) {
            for (int j = 0; j <= lenStr2; j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] = Math.min(
                            Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                            dp[i - 1][j - 1] + (str1.charAt(i - 1) == str2.charAt(j - 1) ? 0 : 1)
                    );
                }
            }
        }
        return dp[lenStr1][lenStr2];
    }

    private static String extractDomainFromUrl(String url) {
        try {
            URI uri = new URI(url);
            return uri.getHost();
        } catch (URISyntaxException e) {
            return "";
        }
    }

    private static void loadMaliciousDomains(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    MALICIOUS_DOMAINS.add(line.trim());
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading malicious domains file: " + e.getMessage());
        }
    }
}
