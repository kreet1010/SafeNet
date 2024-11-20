package com.phishingdetection.utils;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.json.JSONObject;

public class Analysis {
    private static final String GOOGLE_API_KEY = "AIzaSyCl7srC_SIUFY8q0Wrua1NYxWaJWmA_w2g";
    private static final String VIRUSTOTAL_API_KEY = "9ebf6a2e0042fc0d4f9874bea87828d68893e6924630d7e29b0a7c68e62ea948";

    public static boolean isMaliciousWithGoogleSafeBrowsing(String domain) {
        try {
            String url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GOOGLE_API_KEY;
            String payload = "{\"client\":{\"clientId\":\"yourcompany\",\"clientVersion\":\"1.0\"}," +
                    "\"threatInfo\":{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\"]," +
                    "\"platformTypes\":[\"ANY_PLATFORM\"]," +
                    "\"threatEntryTypes\":[\"URL\"]," +
                    "\"threatEntries\":[{\"url\":\"" + domain + "\"}]}}";

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.getOutputStream().write(payload.getBytes());

            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder content = new StringBuilder();
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();

            return !content.toString().isEmpty();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean isMaliciousWithVirusTotal(String domain) {
        try {
            String url = "https://www.virustotal.com/api/v3/domains/" + domain;
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("x-apikey", VIRUSTOTAL_API_KEY);

            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder content = new StringBuilder();
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();

            JSONObject jsonResponse = new JSONObject(content.toString());
            JSONObject data = jsonResponse.optJSONObject("data");
            if (data != null && data.has("attributes")) {
                JSONObject attributes = data.getJSONObject("attributes");
                int maliciousVotes = attributes.optInt("last_analysis_stats.malicious", 0);
                return maliciousVotes > 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean isMaliciousWithOpenPhish(String domain) {
        String filePath = "C:/Users/KREET ROUT/Desktop/Sem 7/J-Component/phishing-detection-tool/PhishingDetectionTool/src/main/java/com/phishingdetection/utils/malicious_domains.txt";  
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String knownDomain;
            while ((knownDomain = br.readLine()) != null) {
                if (domain.equalsIgnoreCase(knownDomain.trim())) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }
}
