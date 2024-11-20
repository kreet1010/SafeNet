package com.phishingdetection.detection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

public class PolicyUpdater {

    public static void executeCommand(String command) {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);
        try {
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line); 
                }
            }
            try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String errorLine;
                while ((errorLine = errorReader.readLine()) != null) {
                    System.out.println("ERROR: " + errorLine); 
                }
            }
            if (exitCode != 0) {
                System.out.println("Command failed with exit code: " + exitCode);
            }
        } catch (IOException|InterruptedException e) {
            System.out.println("Error executing command: " + e.getMessage());
        }
    }

    // Password Policy
    public static void applyPasswordPolicy(String OS, String Domain) {
        if ("Windows".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Password Policy (General):");
                // Windows password policy commands
                executeCommand("net accounts /minpwlen:8");
                executeCommand("net accounts /maxpwage:90");
                executeCommand("net accounts /complexity:enabled");
                executeCommand("net accounts /uniquepw:5");
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Password Policy (Enterprise):");
                // Enterprise-level Windows password policy commands
                executeCommand("net accounts /minpwlen:14");
                executeCommand("net accounts /maxpwage:60");
                executeCommand("net accounts /complexity:strong");
                executeCommand("net accounts /uniquepw:10");
            }
        } else if ("Linux".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Password Policy (General):");
                // Linux password policy commands
                executeCommand("chage -M 90 -m 12 username"); // example user policy
                executeCommand("passwd -n 5 username"); // Prevent password reuse
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Password Policy (Enterprise):");
                // Enterprise-level Linux password policy commands
                executeCommand("chage -M 60 -m 16 username"); // example user policy
                executeCommand("passwd -n 10 username"); // Prevent password reuse
            }
        } else {
            System.out.println("Unsupported OS: " + OS);
        }
    }

    // Firewall Policy
    public static void applyFirewallPolicy(String OS, String Domain) {
        if ("Windows".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Firewall Policy (General):");
                // Windows firewall commands
                executeCommand("netsh advfirewall firewall add rule name=\"Allow HTTP\" protocol=TCP dir=in localport=80 action=allow");
                executeCommand("netsh advfirewall firewall add rule name=\"Allow HTTPS\" protocol=TCP dir=in localport=443 action=allow");
                executeCommand("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Firewall Policy (Enterprise):");
                // Enterprise-level Windows firewall commands
                executeCommand("netsh advfirewall firewall add rule name=\"Allow SSH\" protocol=TCP dir=in localport=22 action=allow");
                executeCommand("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
                executeCommand("netsh advfirewall set currentprofile advancedfirewall on");
            }
        } else if ("Linux".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Firewall Policy (General):");
                // Linux firewall commands
                executeCommand("sudo ufw allow 80/tcp");  // Allow HTTP
                executeCommand("sudo ufw allow 443/tcp"); // Allow HTTPS
                executeCommand("sudo ufw default deny incoming");
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Firewall Policy (Enterprise):");
                // Enterprise-level Linux firewall commands
                executeCommand("sudo ufw allow 22/tcp");  // Allow SSH
                executeCommand("sudo ufw enable");
                executeCommand("sudo ufw logging on");
            }
        } else {
            System.out.println("Unsupported OS: " + OS);
        }
    }

    // Audit Logging Policy
    public static void applyAuditLoggingPolicy(String OS, String Domain) {
        if ("Windows".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Audit Logging Policy (General):");
                // Windows audit logging commands
                executeCommand("auditpol /set /subcategory:\"Logon/Logoff\" /success:enable /failure:enable");
                executeCommand("auditpol /set /subcategory:\"Logon/Logoff\" /failure:enable");
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Windows Audit Logging Policy (Enterprise):");
                // Enterprise-level Windows audit logging commands
                executeCommand("auditpol /set /subcategory:\"Logon/Logoff\" /success:enable /failure:enable");
                executeCommand("auditpol /set /subcategory:\"Account Logon\" /success:enable /failure:enable");
                executeCommand("auditpol /set /subcategory:\"Logon/Logoff\" /success:enable");
            }
        } else if ("Linux".equalsIgnoreCase(OS)) {
            if ("General".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Audit Logging Policy (General):");
                // Linux audit logging commands
                executeCommand("sudo auditctl -w /var/log/secure -p wa");
                executeCommand("sudo auditctl -w /etc/passwd -p wa");
            } else if ("Enterprise".equalsIgnoreCase(Domain)) {
                System.out.println("Applying Linux Audit Logging Policy (Enterprise):");
                // Enterprise-level Linux audit logging commands
                executeCommand("sudo auditctl -w /etc/passwd -p wa");
                executeCommand("sudo auditctl -w /etc/sudoers -p wa");
                executeCommand("sudo auditctl -e 1");
            }
        } else {
            System.out.println("Unsupported OS: " + OS);
        }
    }

    public void setPolicy(String Os, String Domain, String Policy) {
        try {
            // Validate inputs
            if (!isValidOS(Os)) {
                throw new IllegalArgumentException("Error: Invalid OS. Expected 'Windows' or 'Linux'.");
            }
            
            if (!isValidDomain(Domain)) {
                throw new IllegalArgumentException("Error: Invalid Domain. Expected 'General' or 'Enterprise'.");
            }
            
            if (!isValidPolicy(Policy)) {
                throw new IllegalArgumentException("Error: Invalid Policy. Expected 'Password', 'Firewall', or 'AuditLogging'.");
            }
    
            // Apply policies based on valid inputs
            if (Policy.equalsIgnoreCase("Password")) {
                applyPasswordPolicy(Os, Domain);
            } else if (Policy.equalsIgnoreCase("Firewall")) {
                applyFirewallPolicy(Os, Domain);
            } else if (Policy.equalsIgnoreCase("AuditLogging")) {
                applyAuditLoggingPolicy(Os, Domain);
            } else {
                System.out.println("Error: Unknown policy type.");
            }
    
        } catch (IllegalArgumentException e) {
            // Handle invalid inputs
            System.out.println(e.getMessage());
        } catch (Exception e) {
            // Handle other unexpected errors
            System.out.println("An unexpected error occurred: " + e.getMessage());
        }
    }
    
    private static boolean isValidOS(String Os) {
        return Os != null && (Os.equalsIgnoreCase("Windows") || Os.equalsIgnoreCase("Linux"));
    }
    
    private static boolean isValidDomain(String Domain) {
        return Domain != null && (Domain.equalsIgnoreCase("General") || Domain.equalsIgnoreCase("Enterprise"));
    }
    
    private static boolean isValidPolicy(String Policy) {
        return Policy != null && (Policy.equalsIgnoreCase("Password") || Policy.equalsIgnoreCase("Firewall") || Policy.equalsIgnoreCase("AuditLogging"));
    }
    
} 

