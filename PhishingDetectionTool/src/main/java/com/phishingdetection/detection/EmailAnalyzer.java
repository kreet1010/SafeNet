package com.phishingdetection.detection;

import com.phishingdetection.utils.StringUtils;
import com.phishingdetection.utils.LoggerUtil;
import com.phishingdetection.utils.Analysis;


public class EmailAnalyzer {

    public boolean isPhishing(String email) {
        String domain = StringUtils.extractDomainFromEmail(email);
        double phishingScore = calculatePhishingScore(domain);
        LoggerUtil.logInfo("Phishing probability for Email address '" + domain + "': " + phishingScore + "%");
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
