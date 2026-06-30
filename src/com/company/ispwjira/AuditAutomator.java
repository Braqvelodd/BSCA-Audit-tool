package com.company.ispwjira;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class AuditAutomator {

    public static class AuditRow {
        // Original CSV Columns
        public String selected = "";
        public String appl = "";
        public String type = "";
        public String name = "";
        public String ver = "";
        public String action = "";
        public String releaseId = "";
        public String date = "";
        public String time = "";
        public String path = "";
        
        // Jira / Audit Columns
        public String jiraNum = "";
        public String workType = "";
        public String test1 = "";
        public String test2 = "";
        public String test3 = "";
        public String test4 = "";
        public String test5 = "";
        public String test6 = ""; // 100% manual check
        public String notes = "";

        public AuditRow() {}

        public AuditRow(String selected, String appl, String type, String name, String ver, String action, String releaseId, String date, String time, String path) {
            this.selected = selected;
            this.appl = appl;
            this.type = type;
            this.name = name;
            this.ver = ver;
            this.action = action;
            this.releaseId = releaseId;
            this.date = date;
            this.time = time;
            this.path = path;
        }

        public String toCsvOutputString() {
            return String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                    escapeCsv(selected),
                    escapeCsv(appl),
                    escapeCsv(type),
                    escapeCsv(name),
                    escapeCsv(ver),
                    escapeCsv(action),
                    escapeCsv(releaseId),
                    escapeCsv(date),
                    escapeCsv(time),
                    escapeCsv(path),
                    escapeCsv(jiraNum),
                    escapeCsv(workType),
                    escapeCsv(test1),
                    escapeCsv(test2),
                    escapeCsv(test3),
                    escapeCsv(test4),
                    escapeCsv(test5),
                    escapeCsv(test6),
                    escapeCsv(notes)
            );
        }

        private String escapeCsv(String value) {
            if (value == null) return "";
            String trimmed = value.trim();
            if (trimmed.contains(",") || trimmed.contains("\"") || trimmed.contains("\n")) {
                return "\"" + trimmed.replace("\"", "\"\"") + "\"";
            }
            return trimmed;
        }
    }

    private final String certAlias;
    private final String jiraUrl;
    private final boolean devMode;
    private CloseableHttpClient httpClient;
    private final ExecutorService rowExecutorService = Executors.newFixedThreadPool(5);
    private final ExecutorService subtaskExecutorService = Executors.newFixedThreadPool(20);
    
    // Stores the metadata header lines from the CSV (e.g. lines 1 to 37)
    public static final List<String> metadataHeaderLines = new ArrayList<>();

    public AuditAutomator(String certAlias, String jiraUrl, boolean devMode) {
        this.certAlias = certAlias;
        this.jiraUrl = jiraUrl;
        this.devMode = devMode;
    }

    public void initHttpClient() throws Exception {
        if (devMode) {
            AuditLogger.info("Initializing HTTP Client in DEV (Mock Interceptor) Mode.");
            this.httpClient = HttpClients.createDefault();
            return;
        }

        SSLContext sslContext;
        SSLConnectionSocketFactory sslSocketFactory;

        if (certAlias == null || certAlias.isEmpty()) {
            AuditLogger.fatal("FATAL: Valid DoD PKI certificate not selected.");
            throw new IllegalStateException("Valid DoD PKI certificate not selected.");
        }

        AuditLogger.info("Configuring SSLContext with certificate alias: " + certAlias);
        KeyStore keyStore = CertificateManager.getWindowsKeyStore();

        sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, null, new PrivateKeyStrategy() {
                    @Override
                    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
                        if (aliases.containsKey(certAlias)) {
                            AuditLogger.info("Successfully bound client cert alias: " + certAlias);
                            return certAlias;
                        }
                        AuditLogger.warn("Certificate alias not found in active socket list: " + certAlias);
                        return null;
                    }
                })
                .loadTrustMaterial(new TrustAllStrategy())
                .build();

        sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                NoopHostnameVerifier.INSTANCE
        );

        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", sslSocketFactory)
                .build();

        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        connManager.setMaxTotal(50);
        connManager.setDefaultMaxPerRoute(50);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(10000)
                .setSocketTimeout(10000)
                .build();

        this.httpClient = HttpClients.custom()
                .setConnectionManager(connManager)
                .setDefaultRequestConfig(requestConfig)
                .build();

        AuditLogger.info("Secure HTTP Client successfully initialized with CAC Certificate & Connection Pooling.");
    }

    public void close() {
        if (httpClient != null) {
            try {
                httpClient.close();
            } catch (IOException e) {
                AuditLogger.error("Failed to close HttpClient: " + e.getMessage());
            }
        }
        rowExecutorService.shutdown();
        subtaskExecutorService.shutdown();
        try {
            if (!rowExecutorService.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) {
                rowExecutorService.shutdownNow();
            }
            if (!subtaskExecutorService.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) {
                subtaskExecutorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            rowExecutorService.shutdownNow();
            subtaskExecutorService.shutdownNow();
        }
    }

    public void runAudit(List<AuditRow> rows) {
        AuditLogger.info("Starting audit run on " + rows.size() + " rows.");
        List<Future<?>> rowFutures = new ArrayList<>();

        for (int i = 0; i < rows.size(); i++) {
            final AuditRow row = rows.get(i);
            final int index = i;

            // Skip rows without SELECTED=Y to avoid unnecessary API hits on unselected data
            if (!"Y".equalsIgnoreCase(row.selected)) {
                continue;
            }

            rowFutures.add(rowExecutorService.submit(new Runnable() {
                @Override
                public void run() {
                    AuditLogger.info("Auditing row " + (index + 1) + "/" + rows.size() + " - Release ID: " + row.releaseId);
                    try {
                        row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
                        if (row.test6 == null || row.test6.trim().isEmpty()) {
                            row.test6 = "N";
                        }
                        auditSingleRow(row);
                    } catch (Exception e) {
                        row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
                        row.notes = "Unhandled exception: " + e.getMessage();
                        AuditLogger.error("Error auditing row " + row.releaseId + ": " + e.getMessage());
                    }
                }
            }));
        }

        // Wait for all parallel row audits to complete
        for (Future<?> f : rowFutures) {
            try {
                f.get();
            } catch (Exception e) {
                AuditLogger.error("Error waiting for row audit task: " + e.getMessage());
            }
        }
        AuditLogger.info("Audit run completed.");
    }

    private void auditSingleRow(AuditRow row) throws Exception {
        if (row.releaseId == null || row.releaseId.isEmpty()) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Missing Release ID in CSV row.";
            return;
        }

        // 1. Resolve JQL Search
        String jqlQuery = "project = TFS AND comment ~ \"" + row.releaseId + "\" AND issuetype != 'Sub-task'";
        String searchUrl = jiraUrl + "/rest/api/2/search?jql=" + URLEncoder.encode(jqlQuery, "UTF-8");

        String searchResultJson = executeHttpGetWithRetry(searchUrl);
        if (searchResultJson == null) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Jira API unreachable.";
            return;
        }

        JsonObject searchResponse = JsonParser.parseString(searchResultJson).getAsJsonObject();
        JsonArray issues = searchResponse.getAsJsonArray("issues");
        int totalIssues = searchResponse.get("total").getAsInt();

        if (totalIssues == 0 || issues == null || issues.size() == 0) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "No linked Jira Epic found for Release ID.";
            AuditLogger.warn("JQL returned 0 results for Release ID: " + row.releaseId);
            return;
        }

        if (totalIssues > 1) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "REVIEW";
            row.notes = "Multiple Jira Epics mention this Release ID. Human review required.";
            AuditLogger.warn("Multiple Jira Epics (" + totalIssues + ") found for Release ID: " + row.releaseId);
            return;
        }

        JsonObject issue = issues.get(0).getAsJsonObject();
        String epicKey = issue.get("key").getAsString();
        row.jiraNum = epicKey;

        // 2. Fetch Epic Payload
        String epicUrl = jiraUrl + "/rest/api/2/issue/" + epicKey;
        String epicDetailsJson = executeHttpGetWithRetry(epicUrl);
        if (epicDetailsJson == null) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Failed to fetch Epic details.";
            return;
        }

        JsonObject epicPayload = JsonParser.parseString(epicDetailsJson).getAsJsonObject();
        JsonObject fields = epicPayload.getAsJsonObject("fields");
        if (fields == null) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Epic fields are null.";
            return;
        }

        // --- Execute Audit Tests ---
        
        // TEST 1: Valid work type (Epic, Story)
        try {
            JsonObject issueType = fields.getAsJsonObject("issuetype");
            String typeName = issueType != null ? issueType.get("name").getAsString() : "";
            if ("Epic".equalsIgnoreCase(typeName)) {
                row.workType = "SCR";
            } else {
                row.workType = typeName;
            }
            if ("Epic".equalsIgnoreCase(typeName) || "Story".equalsIgnoreCase(typeName)) {
                row.test1 = "Y";
            } else {
                row.test1 = "N";
                AuditLogger.warn(epicKey + " TEST 1 Failed: Issue type is " + typeName);
            }
        } catch (Exception e) {
            row.test1 = "N";
        }

        // TEST 2: Proper authorization
        try {
            JsonObject statusObj = fields.getAsJsonObject("status");
            String statusName = statusObj != null ? statusObj.get("name").getAsString() : "";
            JsonElement authField = fields.get("customfield_auth");
            String authFieldValue = (authField != null && !authField.isJsonNull()) ? authField.getAsString() : null;

            if ("Approved".equalsIgnoreCase(statusName) || "Released".equalsIgnoreCase(statusName) ||
                "Done".equalsIgnoreCase(statusName) || "Resolved".equalsIgnoreCase(statusName) || 
                (authFieldValue != null && !authFieldValue.trim().isEmpty())) {
                row.test2 = "Y";
            } else {
                row.test2 = "N";
                AuditLogger.warn(epicKey + " TEST 2 Failed: Status is " + statusName);
            }
        } catch (Exception e) {
            row.test2 = "N";
        }

        // TEST 3 & TEST 4: Subtask checks in parallel (up to 5 threads at a time)
        try {
            JsonArray subtasks = fields.getAsJsonArray("subtasks");
            if (subtasks == null || subtasks.size() == 0) {
                row.test3 = "N";
                row.test4 = "N";
                AuditLogger.warn(epicKey + " TEST 3 & 4 Failed: No sub-tasks found.");
            } else {
                final String searchString = (row.type.trim() + " " + row.name.trim()).toLowerCase();
                final AtomicBoolean test3Passed = new AtomicBoolean(false);
                final AtomicBoolean qaPassed = new AtomicBoolean(false);
                final AtomicBoolean qaTaskFound = new AtomicBoolean(false);

                List<Future<?>> futures = new ArrayList<>();

                for (JsonElement subEl : subtasks) {
                    JsonObject subtaskObj = subEl.getAsJsonObject();
                    final String subtaskKey = subtaskObj.get("key").getAsString();

                    futures.add(subtaskExecutorService.submit(new Runnable() {
                        @Override
                        public void run() {
                            // Short circuit if we already resolved both test 3 (pass) and test 4 (pass)
                            if (test3Passed.get() && qaPassed.get()) {
                                return;
                            }

                            try {
                                String subtaskUrl = jiraUrl + "/rest/api/2/issue/" + subtaskKey;
                                String subtaskJson = executeHttpGetWithRetry(subtaskUrl);
                                if (subtaskJson == null) return;

                                JsonObject subPayload = JsonParser.parseString(subtaskJson).getAsJsonObject();
                                JsonObject subFields = subPayload.getAsJsonObject("fields");
                                if (subFields == null) return;

                                String summary = subFields.get("summary") != null ? subFields.get("summary").getAsString() : "";
                                String description = subFields.get("description") != null && !subFields.get("description").isJsonNull()
                                        ? subFields.get("description").getAsString() : "";

                                // TEST 3 check: Starts with in summary, OR contains in description
                                boolean matchSummary = summary.toLowerCase().trim().startsWith(searchString);
                                boolean matchDesc = description.toLowerCase().contains(searchString);

                                if (matchSummary || matchDesc) {
                                    test3Passed.set(true);
                                }

                                // TEST 4 check: Locate QA/testing sub-task and verify status
                                boolean isQaTask = summary.toLowerCase().contains("qa") || summary.toLowerCase().contains("test");
                                if (isQaTask) {
                                    qaTaskFound.set(true);
                                    JsonObject subStatus = subFields.getAsJsonObject("status");
                                    String subStatusName = subStatus != null ? subStatus.get("name").getAsString() : "";
                                    if ("Passed".equalsIgnoreCase(subStatusName) ||
                                        "Accepted".equalsIgnoreCase(subStatusName) ||
                                        "Done".equalsIgnoreCase(subStatusName)) {
                                        qaPassed.set(true);
                                    }
                                }
                            } catch (Exception ex) {
                                AuditLogger.error("Failed to query subtask " + subtaskKey + ": " + ex.getMessage());
                            }
                        }
                    }));
                }

                // Wait for all parallel sub-task checks to complete
                for (Future<?> f : futures) {
                    try {
                        f.get();
                    } catch (Exception ex) {}
                }

                row.test3 = test3Passed.get() ? "Y" : "N";
                if (qaTaskFound.get()) {
                    row.test4 = qaPassed.get() ? "Y" : "N";
                } else {
                    row.test4 = "N";
                }
            }
        } catch (Exception e) {
            row.test3 = "N";
            row.test4 = "N";
        }

        // TEST 5: Project approved for release (fixVersions[0].released == true)
        try {
            JsonArray fixVersions = fields.getAsJsonArray("fixVersions");
            if (fixVersions != null && fixVersions.size() > 0) {
                JsonObject firstVersion = fixVersions.get(0).getAsJsonObject();
                JsonElement releasedEl = firstVersion.get("released");
                if (releasedEl != null && releasedEl.getAsBoolean()) {
                    row.test5 = "Y";
                } else {
                    row.test5 = "N";
                }
            } else {
                row.test5 = "N";
            }
        } catch (Exception e) {
            row.test5 = "N";
        }

        row.notes = "Audit successful.";
    }

    private String executeHttpGetWithRetry(String url) throws Exception {
        if (devMode) {
            MockJiraServer.MockResponse mockResp = MockJiraServer.handleRequest(url);
            if (mockResp.statusCode == 429) {
                String retryAfterStr = mockResp.headers.get("Retry-After");
                int retrySec = retryAfterStr != null ? Integer.parseInt(retryAfterStr) : 2;
                AuditLogger.warn("Received HTTP 429 Rate Limit (MOCK). Retrying in " + retrySec + " seconds...");
                Thread.sleep(retrySec * 1000L);
                mockResp = MockJiraServer.handleRequest(url);
            }
            return mockResp.body;
        }

        int retries = 0;
        int maxRetries = 3;
        while (retries < maxRetries) {
            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 200) {
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity) : null;
                } else if (statusCode == 429) {
                    Header retryHeader = response.getFirstHeader("Retry-After");
                    int waitSeconds = 2;
                    if (retryHeader != null) {
                        try {
                            waitSeconds = Integer.parseInt(retryHeader.getValue());
                        } catch (NumberFormatException nfe) {}
                    }
                    AuditLogger.warn("Received HTTP 429 Rate Limit. Retrying in " + waitSeconds + " seconds...");
                    Thread.sleep(waitSeconds * 1000L);
                    retries++;
                } else {
                    AuditLogger.error("Jira API returned error code " + statusCode + " for URL: " + url);
                    return null;
                }
            } catch (Exception e) {
                AuditLogger.error("HTTP request failed: " + e.getMessage());
                throw e;
            }
        }
        return null;
    }

    public static List<AuditRow> parseCsvReport(File file) throws IOException {
        List<AuditRow> list = new ArrayList<>();
        metadataHeaderLines.clear();
        
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            boolean headerFound = false;
            
            while ((line = br.readLine()) != null) {
                if (!headerFound) {
                    // Check if this is the column header line
                    if (line.startsWith("SELECTED") || line.contains("SELECTED,APPL")) {
                        headerFound = true;
                        // We do not add the header row to metadataHeaderLines, we write it manually during export
                        continue;
                    }
                    metadataHeaderLines.add(line);
                    continue;
                }
                
                if (line.trim().isEmpty()) continue;
                
                List<String> values = parseCsvLine(line);
                if (values.size() >= 7) {
                    AuditRow row = new AuditRow();
                    row.selected = getValueOrEmpty(values, 0);
                    row.appl = getValueOrEmpty(values, 1);
                    row.type = getValueOrEmpty(values, 2);
                    row.name = getValueOrEmpty(values, 3);
                    row.ver = getValueOrEmpty(values, 4);
                    row.action = getValueOrEmpty(values, 5);
                    row.releaseId = getValueOrEmpty(values, 6);
                    row.date = getValueOrEmpty(values, 7);
                    row.time = getValueOrEmpty(values, 8);
                    row.path = getValueOrEmpty(values, 9);
                    
                    // Retrieve existing values if present in the source CSV (so we don't clear them)
                    row.jiraNum = getValueOrEmpty(values, 10);
                    row.workType = getValueOrEmpty(values, 11);
                    row.test1 = getNormalizedStatus(getValueOrEmpty(values, 12));
                    row.test2 = getNormalizedStatus(getValueOrEmpty(values, 13));
                    row.test3 = getNormalizedStatus(getValueOrEmpty(values, 14));
                    row.test4 = getNormalizedStatus(getValueOrEmpty(values, 15));
                    row.test5 = getNormalizedStatus(getValueOrEmpty(values, 16));
                    row.test6 = getNormalizedStatus(getValueOrEmpty(values, 17));
                    row.notes = getValueOrEmpty(values, 18);
                    
                    list.add(row);
                } else {
                    AuditLogger.warn("Skipping invalid CSV data line: " + line);
                }
            }
        }
        return list;
    }

    private static String getValueOrEmpty(List<String> list, int index) {
        if (index >= 0 && index < list.size()) {
            return list.get(index);
        }
        return "";
    }

    private static String getNormalizedStatus(String val) {
        String clean = val.trim().toUpperCase();
        if (clean.equals("Y") || clean.equals("N") || clean.equals("REVIEW")) {
            return clean;
        }
        return ""; // default to empty
    }

    public static void writeCsvReport(File file, List<AuditRow> rows) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            // 1. Write the original metadata lines
            for (String meta : metadataHeaderLines) {
                bw.write(meta);
                bw.newLine();
            }
            
            // 2. Write the standard 19-column header
            bw.write("SELECTED,APPL,TYPE,NAME,VER,ACTION,RELEASE,DATE,TIME,PATH,JIRA #,WORK TYPE,TEST 1,TEST 2,TEST 3,TEST 4,TEST 5,TEST 6,NOTES");
            bw.newLine();
            
            // 3. Write rows
            for (AuditRow row : rows) {
                bw.write(row.toCsvOutputString());
                bw.newLine();
            }
        }
    }

    private static List<String> parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                values.add(sb.toString().trim());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        values.add(sb.toString().trim());
        return values;
    }
}
