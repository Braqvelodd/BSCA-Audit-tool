package com.company.ispwjira;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class CertificateManager {
    public static class CertInfo {
        private final String alias;
        private final String subjectDN;
        private final boolean isValid;

        public CertInfo(String alias, String subjectDN, boolean isValid) {
            this.alias = alias;
            this.subjectDN = subjectDN;
            this.isValid = isValid;
        }

        public String getAlias() { return alias; }
        public String getSubjectDN() { return subjectDN; }
        public boolean isValid() { return isValid; }

        @Override
        public String toString() {
            return alias + " [" + (isValid ? "Valid" : "Expired/Invalid") + "] - " + subjectDN;
        }
    }

    public static List<CertInfo> getAvailableCertificates() {
        List<CertInfo> certs = new ArrayList<>();
        
        // Always include mock certificates if in Dev Mode for testing purposes
        if (ConfigManager.isDevMode()) {
            certs.add(new CertInfo("MOCK-CAC-DEV-001", "CN=JOHN.DOE.1234567890, OU=CONTRACTOR, OU=PKI, OU=DoD, O=U.S. Government, C=US", true));
            certs.add(new CertInfo("MOCK-CAC-DEV-002", "CN=JANE.SMITH.0987654321, OU=USAF, OU=PKI, OU=DoD, O=U.S. Government, C=US", true));
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("Windows-MY");
            keyStore.load(null, null);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    if (cert != null) {
                        boolean isValid = true;
                        try {
                            cert.checkValidity();
                        } catch (Exception e) {
                            isValid = false;
                        }
                        certs.add(new CertInfo(alias, cert.getSubjectDN().getName(), isValid));
                    }
                }
            }
        } catch (Exception e) {
            AuditLogger.warn("Could not access Windows-MY keystore: " + e.getMessage() + ". (Ignore if not on Windows).");
        }

        return certs;
    }

    public static KeyStore getWindowsKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("Windows-MY");
        keyStore.load(null, null);
        return keyStore;
    }
}
