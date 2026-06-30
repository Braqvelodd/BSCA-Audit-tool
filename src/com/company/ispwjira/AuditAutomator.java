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

        public final List<String> traceLogs = new java.util.concurrent.CopyOnWriteArrayList<>();
        public void addTrace(String msg) {
            traceLogs.add(msg);
        }

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
    private final boolean traceLoggingEnabled;
    private CloseableHttpClient httpClient;
    private final ExecutorService rowExecutorService = Executors.newFixedThreadPool(5);
    private final ExecutorService subtaskExecutorService = Executors.newFixedThreadPool(20);
    
    // Stores the metadata header lines from the CSV (e.g. lines 1 to 37)
    public static final List<String> metadataHeaderLines = new ArrayList<>();

    public AuditAutomator(String certAlias, String jiraUrl, boolean traceLoggingEnabled) {
        this.certAlias = certAlias;
        this.jiraUrl = jiraUrl;
        this.traceLoggingEnabled = traceLoggingEnabled;
    }

    public void initHttpClient() throws Exception {

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
                    } finally {
                        if (traceLoggingEnabled) {
                            synchronized (AuditLogger.class) {
                                AuditLogger.info("\n--------------------------------------------------");
                                AuditLogger.info("TRACE LOGS FOR ROW " + (index + 1) + " (Release ID: " + row.releaseId + ", CI: " + row.type + " " + row.name + "):");
                                for (String log : row.traceLogs) {
                                    AuditLogger.info(log);
                                }
                                AuditLogger.info("--------------------------------------------------\n");
                            }
                        }
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

    private void auditSingleRow(final AuditRow row) throws Exception {
        if (row.releaseId == null || row.releaseId.isEmpty()) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Missing Release ID in CSV row.";
            return;
        }

        row.addTrace("[TRACE] Auditing Release ID '" + row.releaseId + "', CI Type: '" + row.type + "', CI Name: '" + row.name + "'");

        boolean isSrRelease = row.releaseId.trim().toUpperCase().startsWith("SR");
        boolean taskLinkSuccess = false;

        if (isSrRelease) {
            // 1. Task-Link Path (Primary Path)
            try {
                row.addTrace("[TRACE] Path 1 (Task-Link): Querying JIRA sub-tasks containing summary '" + row.releaseId + "'...");
                String subtaskJql = "project = TFS AND issuetype = Sub-task AND summary ~ \"" + row.releaseId + "\"";
                String subtaskSearchUrl = jiraUrl + "/rest/api/2/search?jql=" + URLEncoder.encode(subtaskJql, "UTF-8") + "&maxResults=1000";
                String subtaskSearchJson = executeHttpGetWithRetry(subtaskSearchUrl);
                
                if (subtaskSearchJson != null) {
                    JsonObject subtaskSearchResponse = JsonParser.parseString(subtaskSearchJson).getAsJsonObject();
                    JsonArray subtasksFound = subtaskSearchResponse.getAsJsonArray("issues");
                    int subtaskCount = subtaskSearchResponse.get("total").getAsInt();
                    row.addTrace("[TRACE] Path 1: Found " + subtaskCount + " sub-tasks with summary matching '" + row.releaseId + "'");
                    
                    if (subtasksFound != null && subtasksFound.size() > 0) {
                        final String typeNorm = row.type.trim().toLowerCase();
                        final String nameNorm = row.name.trim().toLowerCase();
                        final String combinedNorm = (typeNorm + " " + nameNorm);
                        row.addTrace("[TRACE] Path 1: Searching sub-task descriptions for: '" + combinedNorm + "' or separately: ['" + typeNorm + "', '" + nameNorm + "']");

                        for (JsonElement subEl : subtasksFound) {
                            JsonObject subtask = subEl.getAsJsonObject();
                            final String subtaskKey = subtask.get("key").getAsString();
                            JsonObject fieldsObj = subtask.getAsJsonObject("fields");
                            if (fieldsObj == null) continue;

                            String description = fieldsObj.get("description") != null && !fieldsObj.get("description").isJsonNull()
                                    ? fieldsObj.get("description").getAsString() : "";
                            String descLower = description.toLowerCase();

                            // Match logic: Combined type+name OR both type and name separately
                            boolean descMatched = descLower.contains(combinedNorm) || 
                                                  (descLower.contains(typeNorm) && descLower.contains(nameNorm));

                            row.addTrace("[TRACE] Path 1: Checking sub-task " + subtaskKey + " description (length: " + descLower.length() + "). Match status: " + descMatched);

                            if (descMatched) {
                                JsonObject parentObj = fieldsObj.getAsJsonObject("parent");
                                if (parentObj != null) {
                                    final String parentTaskKey = parentObj.get("key").getAsString();
                                    row.addTrace("[TRACE] Path 1 SUCCESS: Found linking Task: " + parentTaskKey + " via sub-task: " + subtaskKey);

                                    // Fetch the parent Task's full details
                                    String parentUrl = jiraUrl + "/rest/api/2/issue/" + parentTaskKey;
                                    String parentJson = executeHttpGetWithRetry(parentUrl);
                                    if (parentJson != null) {
                                        JsonObject parentPayload = JsonParser.parseString(parentJson).getAsJsonObject();
                                        JsonObject parentFields = parentPayload.getAsJsonObject("fields");
                                        
                                        if (parentFields != null) {
                                            JsonArray taskSubtasks = parentFields.getAsJsonArray("subtasks");
                                            if (taskSubtasks != null && taskSubtasks.size() > 0) {
                                                row.addTrace("[TRACE] Path 1: Parent Task " + parentTaskKey + " has " + taskSubtasks.size() + " sub-tasks.");
                                                
                                                // Identify other sub-tasks not containing the releaseId in summary
                                                List<String> otherSubtaskKeys = new ArrayList<>();
                                                for (JsonElement tSubEl : taskSubtasks) {
                                                    JsonObject tSub = tSubEl.getAsJsonObject();
                                                    String tSubKey = tSub.get("key").getAsString();
                                                    JsonObject tSubFields = tSub.getAsJsonObject("fields");
                                                    String tSubSummary = "";
                                                    if (tSubFields != null && tSubFields.get("summary") != null) {
                                                        tSubSummary = tSubFields.get("summary").getAsString();
                                                    }
                                                    
                                                    if (!tSubSummary.toLowerCase().contains(row.releaseId.toLowerCase())) {
                                                        otherSubtaskKeys.add(tSubKey);
                                                    }
                                                }

                                                row.addTrace("[TRACE] Path 1: Found " + otherSubtaskKeys.size() + " other sub-tasks to check links: " + otherSubtaskKeys);

                                                // Query the other sub-tasks in parallel to find linked Epics
                                                final List<String> linkedCandidateKeys = new java.util.concurrent.CopyOnWriteArrayList<>();
                                                List<Future<?>> subtaskDetailFutures = new ArrayList<>();
                                                for (final String tSubKey : otherSubtaskKeys) {
                                                    subtaskDetailFutures.add(subtaskExecutorService.submit(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            try {
                                                                String tSubUrl = jiraUrl + "/rest/api/2/issue/" + tSubKey;
                                                                String tSubJson = executeHttpGetWithRetry(tSubUrl);
                                                                if (tSubJson != null) {
                                                                    JsonObject tSubPayload = JsonParser.parseString(tSubJson).getAsJsonObject();
                                                                    JsonObject tSubFields = tSubPayload.getAsJsonObject("fields");
                                                                    if (tSubFields != null) {
                                                                        JsonArray issuelinks = tSubFields.getAsJsonArray("issuelinks");
                                                                        int linksFound = (issuelinks != null) ? issuelinks.size() : 0;
                                                                        row.addTrace("[TRACE] Path 1: Sub-task " + tSubKey + " has " + linksFound + " issue links.");
                                                                        if (issuelinks != null) {
                                                                            for (JsonElement linkEl : issuelinks) {
                                                                                JsonObject link = linkEl.getAsJsonObject();
                                                                                JsonObject targetIssue = null;
                                                                                if (link.has("inwardIssue")) {
                                                                                    targetIssue = link.getAsJsonObject("inwardIssue");
                                                                                } else if (link.has("outwardIssue")) {
                                                                                    targetIssue = link.getAsJsonObject("outwardIssue");
                                                                                }
                                                                                
                                                                                if (targetIssue != null) {
                                                                                    String targetKey = targetIssue.get("key").getAsString();
                                                                                    if (!linkedCandidateKeys.contains(targetKey)) {
                                                                                        linkedCandidateKeys.add(targetKey);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            } catch (Exception ex) {
                                                                AuditLogger.error("[TRACE] Failed to fetch sub-task links for " + tSubKey + ": " + ex.getMessage());
                                                            }
                                                        }
                                                    }));
                                                }

                                                // Wait for all links to be extracted
                                                for (Future<?> f : subtaskDetailFutures) {
                                                    try { f.get(); } catch (Exception e) {}
                                                }

                                                row.addTrace("[TRACE] Path 1: Aggregated candidate Epic keys from links: " + linkedCandidateKeys);

                                                // Query all of these candidate Epics' payloads in one JQL search
                                                if (!linkedCandidateKeys.isEmpty()) {
                                                    StringBuilder jqlBuilder = new StringBuilder("key in (");
                                                    for (int i = 0; i < linkedCandidateKeys.size(); i++) {
                                                        jqlBuilder.append(linkedCandidateKeys.get(i));
                                                        if (i < linkedCandidateKeys.size() - 1) {
                                                            jqlBuilder.append(",");
                                                        }
                                                    }
                                                    jqlBuilder.append(")");
                                                    
                                                    String epicsUrl = jiraUrl + "/rest/api/2/search?jql=" + URLEncoder.encode(jqlBuilder.toString(), "UTF-8") + "&maxResults=1000";
                                                    String epicsJson = executeHttpGetWithRetry(epicsUrl);
                                                    if (epicsJson != null) {
                                                        JsonObject epicsResponse = JsonParser.parseString(epicsJson).getAsJsonObject();
                                                        JsonArray epicsList = epicsResponse.getAsJsonArray("issues");
                                                        if (epicsList != null && epicsList.size() > 0) {
                                                            row.addTrace("[TRACE] Path 1: Inspecting sub-tasks under linked candidate Epics...");
                                                            taskLinkSuccess = performCandidateInspection(row, epicsList);
                                                            if (taskLinkSuccess) {
                                                                return; // Finished auditing row!
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    row.addTrace("[TRACE] Path 1: No candidate Epic keys were linked to the other sub-tasks of Task " + parentTaskKey);
                                                }
                                            } else {
                                                row.addTrace("[TRACE] Path 1: Parent Task " + parentTaskKey + " has 0 sub-tasks.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        row.addTrace("[TRACE] Path 1: No sub-tasks found matching summary '" + row.releaseId + "'");
                    }
                }
            } catch (Exception ex) {
                row.addTrace("[TRACE] Path 1 ERROR: Exception in Task-Link path: " + ex.getMessage());
            }
        } else {
            row.addTrace("[TRACE] Release ID '" + row.releaseId + "' is not an SR* release. Skipping Path 1 (Task-Link)...");
        }

        // 2. Direct Comment Path (Fallback Path)
        row.addTrace("[TRACE] Path 2: Querying JIRA comments for Release ID '" + row.releaseId + "'...");
        String fallbackJql = "project = TFS AND comment ~ \"" + row.releaseId + "\"";
        String fallbackUrl = jiraUrl + "/rest/api/2/search?jql=" + URLEncoder.encode(fallbackJql, "UTF-8") + "&maxResults=1000";

        String fallbackJson = executeHttpGetWithRetry(fallbackUrl);
        if (fallbackJson == null) {
            row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
            row.notes = "Jira API unreachable on fallback path.";
            return;
        }

        JsonObject fbResponse = JsonParser.parseString(fallbackJson).getAsJsonObject();
        JsonArray fbCandidates = fbResponse.getAsJsonArray("issues");
        int fbTotal = fbResponse.get("total").getAsInt();
        row.addTrace("[TRACE] Path 2: Found " + fbTotal + " candidate issues via direct comments search.");
        
        if (fbCandidates != null && fbCandidates.size() > 0) {
            row.addTrace("[TRACE] Path 2: Inspecting sub-tasks under comment-linked candidate issues...");
            boolean fallbackSuccess = performCandidateInspection(row, fbCandidates);
            if (fallbackSuccess) {
                return; // Finished auditing row!
            }
        }

        // If we reach here, neither path found a match!
        row.test1 = row.test2 = row.test3 = row.test4 = row.test5 = "N";
        row.notes = "No matching sub-task found for type/name under candidates on both paths.";
        row.addTrace("[TRACE] FAILED: Release ID '" + row.releaseId + "' audit complete. No matching sub-task found on either path.");
    }

    private boolean performCandidateInspection(final AuditRow row, JsonArray candidates) throws Exception {
        for (JsonElement candEl : candidates) {
            JsonObject candidate = candEl.getAsJsonObject();
            final String candidateKey = candidate.get("key").getAsString();
            JsonObject candFields = candidate.getAsJsonObject("fields");
            if (candFields == null) continue;

            JsonObject candTypeObj = candFields.getAsJsonObject("issuetype");
            String candTypeName = candTypeObj != null ? candTypeObj.get("name").getAsString() : "";

            row.addTrace("[TRACE] Inspecting candidate: " + candidateKey + " (IssueType: " + candTypeName + ")");

            List<SubtaskInspectionTask> inspectionTasks = new ArrayList<>();

            // A. Epic: direct subtasks + child stories' subtasks
            if ("Epic".equalsIgnoreCase(candTypeName)) {
                JsonArray subtasks = candFields.getAsJsonArray("subtasks");
                int directCount = (subtasks != null) ? subtasks.size() : 0;
                row.addTrace("[TRACE] Epic " + candidateKey + " has " + directCount + " direct sub-tasks.");
                if (subtasks != null) {
                    for (JsonElement subEl : subtasks) {
                        inspectionTasks.add(new SubtaskInspectionTask(
                            subEl.getAsJsonObject().get("key").getAsString(),
                            candidateKey,
                            candidate
                        ));
                    }
                }

                try {
                    String storyJql = "\"epic link\" = " + candidateKey + " OR parent = " + candidateKey;
                    row.addTrace("[TRACE] Epic " + candidateKey + ": Querying child stories via: " + storyJql);
                    String storyUrl = jiraUrl + "/rest/api/2/search?jql=" + URLEncoder.encode(storyJql, "UTF-8") + "&maxResults=1000";
                    String storyResultJson = executeHttpGetWithRetry(storyUrl);
                    if (storyResultJson != null) {
                        JsonObject storyResponse = JsonParser.parseString(storyResultJson).getAsJsonObject();
                        JsonArray stories = storyResponse.getAsJsonArray("issues");
                        int storyCount = (stories != null) ? stories.size() : 0;
                        row.addTrace("[TRACE] Epic " + candidateKey + " has " + storyCount + " child stories.");
                        if (stories != null) {
                            for (JsonElement storyEl : stories) {
                                JsonObject story = storyEl.getAsJsonObject();
                                final String storyKey = story.get("key").getAsString();
                                JsonObject storyFields = story.getAsJsonObject("fields");
                                if (storyFields != null) {
                                    JsonObject issueTypeObj = storyFields.getAsJsonObject("issuetype");
                                    String typeName = issueTypeObj != null ? issueTypeObj.get("name").getAsString() : "";
                                    if ("Test".equalsIgnoreCase(typeName) || "Test Execution".equalsIgnoreCase(typeName)) {
                                        row.addTrace("[TRACE] Ignoring child issue " + storyKey + " because its type is: " + typeName);
                                        continue;
                                    }

                                    JsonArray storySubtasks = storyFields.getAsJsonArray("subtasks");
                                    int storySubCount = (storySubtasks != null) ? storySubtasks.size() : 0;
                                    row.addTrace("[TRACE] Child Story " + storyKey + " has " + storySubCount + " sub-tasks.");
                                    if (storySubtasks != null) {
                                        for (JsonElement subEl : storySubtasks) {
                                            inspectionTasks.add(new SubtaskInspectionTask(
                                                subEl.getAsJsonObject().get("key").getAsString(),
                                                storyKey,
                                                story
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ex) {
                    AuditLogger.error("[TRACE] Failed to query child stories for Epic " + candidateKey + ": " + ex.getMessage());
                }
            } else {
                // B. Story, PTR, FCR, etc.
                JsonArray subtasks = candFields.getAsJsonArray("subtasks");
                int subCount = (subtasks != null) ? subtasks.size() : 0;
                row.addTrace("[TRACE] Candidate " + candidateKey + " has " + subCount + " direct sub-tasks.");
                if (subtasks != null) {
                    for (JsonElement subEl : subtasks) {
                        inspectionTasks.add(new SubtaskInspectionTask(
                            subEl.getAsJsonObject().get("key").getAsString(),
                            candidateKey,
                            candidate
                        ));
                    }
                }
            }

            row.addTrace("[TRACE] Gathered total of " + inspectionTasks.size() + " sub-task query tasks for candidate " + candidateKey);

            if (!inspectionTasks.isEmpty()) {
                final String searchString = (row.type.trim() + " " + row.name.trim()).toLowerCase();
                final AtomicBoolean test3Passed = new AtomicBoolean(false);
                final AtomicBoolean qaPassed = new AtomicBoolean(false);
                final AtomicBoolean qaTaskFound = new AtomicBoolean(false);
                final AtomicBoolean matched = new AtomicBoolean(false);

                final StringBuilder matchedParentKey = new StringBuilder();
                final List<JsonObject> matchedParentPayload = new ArrayList<>();

                List<Future<?>> subtaskFutures = new ArrayList<>();
                for (final SubtaskInspectionTask task : inspectionTasks) {
                    subtaskFutures.add(subtaskExecutorService.submit(new Runnable() {
                        @Override
                        public void run() {
                            if (matched.get()) {
                                return;
                            }

                            try {
                                String subtaskUrl = jiraUrl + "/rest/api/2/issue/" + task.subtaskKey;
                                String subtaskJson = executeHttpGetWithRetry(subtaskUrl);
                                if (subtaskJson == null) return;

                                JsonObject subPayload = JsonParser.parseString(subtaskJson).getAsJsonObject();
                                JsonObject subFields = subPayload.getAsJsonObject("fields");
                                if (subFields == null) return;

                                String summary = subFields.get("summary") != null ? subFields.get("summary").getAsString() : "";
                                String description = subFields.get("description") != null && !subFields.get("description").isJsonNull()
                                        ? subFields.get("description").getAsString() : "";

                                boolean matchSummary = summary.toLowerCase().trim().startsWith(searchString);
                                boolean matchDesc = description.toLowerCase().contains(searchString);

                                row.addTrace("[TRACE] Comparing sub-task " + task.subtaskKey + " (parent: " + task.parentKey + "): Summary='" + summary + "' StartsWith='" + searchString + "'? " + matchSummary + "; Description Contains='" + searchString + "'? " + matchDesc);

                                if (matchSummary || matchDesc) {
                                    test3Passed.set(true);
                                    synchronized (matched) {
                                        if (!matched.get()) {
                                            matched.set(true);
                                            matchedParentKey.setLength(0);
                                            matchedParentKey.append(task.parentKey);
                                            matchedParentPayload.clear();
                                            matchedParentPayload.add(task.parentPayload);
                                            row.addTrace("[TRACE] MATCH FOUND on sub-task " + task.subtaskKey + "! Setting target parent key to: " + task.parentKey);
                                        }
                                    }
                                }

                                boolean isQaTask = summary.toLowerCase().contains("qa") || summary.toLowerCase().contains("test");
                                if (isQaTask) {
                                    qaTaskFound.set(true);
                                    JsonObject subStatus = subFields.getAsJsonObject("status");
                                    String subStatusName = subStatus != null ? subStatus.get("name").getAsString() : "";
                                    row.addTrace("[TRACE] Found QA task " + task.subtaskKey + " with status: " + subStatusName);
                                    if ("Passed".equalsIgnoreCase(subStatusName) ||
                                        "Accepted".equalsIgnoreCase(subStatusName) ||
                                        "Done".equalsIgnoreCase(subStatusName)) {
                                        qaPassed.set(true);
                                    }
                                }
                            } catch (Exception ex) {
                                AuditLogger.error("Failed to query subtask " + task.subtaskKey + ": " + ex.getMessage());
                            }
                        }
                    }));
                }

                for (Future<?> f : subtaskFutures) {
                    try { f.get(); } catch (Exception ex) {}
                }

                if (matched.get()) {
                    String finalParentKey = matchedParentKey.toString();
                    JsonObject finalParent = matchedParentPayload.get(0);
                    JsonObject finalParentFields = finalParent.getAsJsonObject("fields");

                    row.jiraNum = finalParentKey;
                    row.addTrace("[TRACE] Resolving compliance metrics for matched parent JIRA key: " + finalParentKey);

                    JsonObject issueType = finalParentFields.getAsJsonObject("issuetype");
                    String typeName = issueType != null ? issueType.get("name").getAsString() : "";
                    if ("Epic".equalsIgnoreCase(typeName)) {
                        row.workType = "SCR";
                    } else {
                        row.workType = typeName;
                    }

                    if ("Epic".equalsIgnoreCase(typeName) || "Story".equalsIgnoreCase(typeName) ||
                        "PTR".equalsIgnoreCase(typeName) || "FCR".equalsIgnoreCase(typeName) ||
                        "Utility".equalsIgnoreCase(typeName) || "Extract".equalsIgnoreCase(typeName)) {
                        row.test1 = "Y";
                    } else {
                        row.test1 = "N";
                        AuditLogger.warn(finalParentKey + " TEST 1 Failed: Issue type is " + typeName);
                    }

                    try {
                        JsonObject statusObj = finalParentFields.getAsJsonObject("status");
                        String statusName = statusObj != null ? statusObj.get("name").getAsString() : "";
                        JsonElement authField = finalParentFields.get("customfield_auth");
                        String authFieldValue = (authField != null && !authField.isJsonNull()) ? authField.getAsString() : null;

                        if ("Approved".equalsIgnoreCase(statusName) || "Released".equalsIgnoreCase(statusName) ||
                            "Done".equalsIgnoreCase(statusName) || "Resolved".equalsIgnoreCase(statusName) ||
                            (authFieldValue != null && !authFieldValue.trim().isEmpty())) {
                            row.test2 = "Y";
                        } else {
                            row.test2 = "N";
                            AuditLogger.warn(finalParentKey + " TEST 2 Failed: Status is " + statusName);
                        }
                    } catch (Exception e) {
                        row.test2 = "N";
                    }

                    row.test3 = "Y";

                    if (qaTaskFound.get()) {
                        row.test4 = qaPassed.get() ? "Y" : "N";
                    } else {
                        row.test4 = "N";
                    }

                    try {
                        JsonArray fixVersions = finalParentFields.getAsJsonArray("fixVersions");
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
                    return true;
                }
            }
        }
        return false;
    }

    private String executeHttpGetWithRetry(String url) throws Exception {

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

    private static class SubtaskInspectionTask {
        final String subtaskKey;
        final String parentKey;
        final JsonObject parentPayload;

        SubtaskInspectionTask(String subtaskKey, String parentKey, JsonObject parentPayload) {
            this.subtaskKey = subtaskKey;
            this.parentKey = parentKey;
            this.parentPayload = parentPayload;
        }
    }
}
