package com.company.ispwjira;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigManager {
    private static final String CONFIG_FILE = "config.ini";
    private static final Properties properties = new Properties();

    static {
        // Set defaults
        properties.setProperty("jira.url", "https://jira.example.com");
        properties.setProperty("jira.dev_mode", "true");
        properties.setProperty("user.last_selected_cert", "");
        load();
    }

    public static synchronized void load() {
        File file = new File(CONFIG_FILE);
        if (file.exists()) {
            try (FileInputStream fis = new FileInputStream(file)) {
                properties.load(fis);
                AuditLogger.info("Configuration loaded from " + CONFIG_FILE);
            } catch (IOException e) {
                AuditLogger.error("Failed to load configuration: " + e.getMessage());
            }
        } else {
            AuditLogger.warn(CONFIG_FILE + " not found, using default settings.");
            save(); // Create the file with default settings
        }
    }

    public static synchronized void save() {
        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE)) {
            properties.store(fos, "ISPW-Jira Audit Automator Configuration");
            AuditLogger.info("Configuration saved to " + CONFIG_FILE);
        } catch (IOException e) {
            AuditLogger.error("Failed to save configuration: " + e.getMessage());
        }
    }

    public static String getJiraUrl() {
        return properties.getProperty("jira.url", "https://jira.example.com");
    }

    public static void setJiraUrl(String url) {
        properties.setProperty("jira.url", url);
    }

    public static boolean isDevMode() {
        return Boolean.parseBoolean(properties.getProperty("jira.dev_mode", "false"));
    }

    public static void setDevMode(boolean devMode) {
        properties.setProperty("jira.dev_mode", String.valueOf(devMode));
    }

    public static String getLastSelectedCert() {
        return properties.getProperty("user.last_selected_cert", "");
    }

    public static void setLastSelectedCert(String alias) {
        properties.setProperty("user.last_selected_cert", alias);
    }
}
