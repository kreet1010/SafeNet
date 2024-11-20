package com.phishingdetection.utils;
import java.net.URL;
import java.util.ArrayList;

public class StringUtils {

    public static String extractDomainFromEmail(String email) {
        return email.split("@")[1];
    }
    public static ArrayList<String> extractDomainsFromURL(String url) {
        ArrayList<String> domains = new ArrayList<>();
        try {
            // Parse the URL and get the domain (host) part
            URL parsedUrl = new URL(url);
            String domain = parsedUrl.getHost();
            
            // Add to the list (handling subdomains if needed)
            if (domain.startsWith("www.")) {
                domain = domain.substring(4); // Remove "www." prefix
            }
            domains.add(domain);

        } catch (Exception e) {
            System.err.println("Invalid URL: " + url);
            e.printStackTrace();
        }
        return domains;
    }
}
