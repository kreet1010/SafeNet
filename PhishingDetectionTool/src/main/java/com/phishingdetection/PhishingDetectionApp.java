package com.phishingdetection;

import com.phishingdetection.detection.URLAnalyzer;
import com.phishingdetection.detection.EmailAnalyzer;
import com.phishingdetection.detection.DomainValidator;
import com.phishingdetection.utils.LoggerUtil;
import com.phishingdetection.detection.PolicyUpdater;
import java.util.Scanner;
import java.util.ArrayList;

public class PhishingDetectionApp {
    public static void main(String[] args) {
        // Start the application with an info log
        LoggerUtil.logInfo("Phishing Detection Tool Started.");

        Scanner sc = new Scanner(System.in);
        while (true) {
            // Display options
            System.out.println("Choose the task to perform: \n>> 1. Email verification.\n>> 2. URL verification.\n>> 3. Domain verification.\n>> 4. Security policy implementation.\n>> 5. End Program.");
            int option = sc.nextInt();
            sc.nextLine();
            EmailAnalyzer emailAnalyzer = new EmailAnalyzer();
            URLAnalyzer urlAnalyzer = new URLAnalyzer();
            DomainValidator domainValidator = new DomainValidator();
            PolicyUpdater policyUpdater = new PolicyUpdater();
            switch (option) {
                case 1: // Email analysis
                    System.out.print("# Provide the email address: ");
                    String email = sc.nextLine();
                    ArrayList<String> personals = new ArrayList<>();
                    personals.add("gmail.com");
                    personals.add("yahoo.com");
                    personals.add("yahoo.co.uk");
                    personals.add("ymail.com");
                    personals.add("outlook.com");
                    personals.add("outlook.co.uk");
                    personals.add("outlook.com.au");
                    personals.add("hotmail.com");
                    personals.add("hotmail.co.uk");
                    personals.add("hotmail.fr");
                    personals.add("aol.com");
                    personals.add("icloud.com");
                    personals.add("protonmail.com");
                    personals.add("zoho.com");
                    personals.add("gmx.com");
                    personals.add("gmx.co.uk");
                    personals.add("mail.com");
                    personals.add("yandex.com");
                    personals.add("yandex.ru");
                    personals.add("mail.ru");
                    personals.add("live.com");
                    personals.add("live.co.uk");
                    personals.add("live.fr");
                    personals.add("msn.com");
                    personals.add("fastmail.com");
                    personals.add("tutanota.com");
                    personals.add("hey.com");
                    personals.add("rediffmail.com");
                    personals.add("qq.com");
                    personals.add("lycos.com");
                    personals.add("vitstudent.ac.in");
                    personals.add("vit.ac.in");
                    if(personals.contains(email.split("@")[1])){
                        LoggerUtil.logWarning("Looks Safe, Take action with caution and if sender is trusted : " + email);
                    }
                    else if(emailAnalyzer.isPhishing(email)) {
                        LoggerUtil.logWarning("Phishing email detected: " + email);
                    } else {
                        LoggerUtil.logInfo("Email is safe: " + email);
                    }
                    break;
                case 2: // URL analysis
                    System.out.print("# Provide the URL: ");
                    String url = sc.nextLine();
                    if (urlAnalyzer.isPhishing(url)) {
                        LoggerUtil.logWarning("Phishing URL detected: " + url);
                    } else {
                        LoggerUtil.logInfo("URL is safe: " + url);
                    }
                    break;
                case 3: // Domain analysis
                    System.out.print("# Provide the domain: ");
                    String domain = sc.nextLine();
                    if (domainValidator.isSuspicious(domain)) {
                        LoggerUtil.logWarning("Suspicious domain detected: " + domain);
                    } else {
                        LoggerUtil.logInfo("Domain is safe: " + domain);
                    }
                    break;
                case 4: // Security policy update
                    LoggerUtil.logInfo("Security policy.");
                    System.out.print("# Enter the OS (Windows/Linux): ");
                    String OS = sc.nextLine();
                    System.out.print("# Enter the Domain (General/Enterprise): ");
                    String Domain = sc.nextLine();
                    System.out.print("# Choose Policy (Password/Firewall/Logging): ");
                    String policy = sc.nextLine();
                    policyUpdater.setPolicy(OS,Domain,policy);
                    break;
                case 5: // End program
                    LoggerUtil.logInfo("Phishing Detection Tool Ended.");
                    sc.close();
                    return; 
                default:
                    LoggerUtil.logWarning("Invalid option. Please choose a valid task.");
            }
        }
    }
}
