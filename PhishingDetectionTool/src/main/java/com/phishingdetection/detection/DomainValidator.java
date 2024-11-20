package com.phishingdetection.detection;

import com.phishingdetection.utils.LoggerUtil;
import com.phishingdetection.utils.Analysis;

public class DomainValidator {
    public boolean isSuspicious(String domain) {
        double phishingScore = calculatePhishingScore(domain);
        LoggerUtil.logInfo("Phishing probability for domain '" + domain + "': " + phishingScore + "%");
        return phishingScore > 20.0; 
    }

    private double calculatePhishingScore(String domain) {
        int score = 0;
        int totalChecks = 0;

        if (Analysis.isMaliciousWithGoogleSafeBrowsing(domain)) {
            score += 1;
        }
        totalChecks++;

        if (Analysis.isMaliciousWithVirusTotal(domain)) {
            score += 1;
        }
        totalChecks++;

        if (Analysis.isMaliciousWithOpenPhish(domain)) {
            score += 1;
        }
        totalChecks++;

        return (double) score / totalChecks * 100;
    }
}
