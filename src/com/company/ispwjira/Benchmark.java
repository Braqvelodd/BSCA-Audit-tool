package com.company.ispwjira;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Benchmark {

    public static void main(String[] args) {
        System.out.println("==================================================");
        System.out.println(" JIRA Query Performance Benchmark (Head-to-Head) ");
        System.out.println("==================================================");

        ConfigManager.load();
        String jiraUrl = ConfigManager.getJiraUrl();
        String certAlias = ConfigManager.getLastSelectedCert();

        if (jiraUrl == null || jiraUrl.contains("example.com")) {
            System.out.println("ERROR: Please configure the JIRA URL in the application first.");
            return;
        }
        if (certAlias == null || certAlias.isEmpty()) {
            System.out.println("ERROR: Please select your CAC Certificate in the application first.");
            return;
        }

        System.out.println("JIRA URL: " + jiraUrl);
        System.out.println("Certificate Alias: " + certAlias);
        System.out.println();

        List<String> keys = new ArrayList<>();
        if (args.length > 0) {
            keys.addAll(Arrays.asList(args));
        } else {
            System.out.println("Enter comma-separated JIRA sub-task keys to test (e.g., TFS-101, TFS-102, TFS-103):");
            try (Scanner scanner = new Scanner(System.in)) {
                if (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (line != null && !line.trim().isEmpty()) {
                        for (String part : line.split(",")) {
                            String k = part.trim();
                            if (!k.isEmpty()) {
                                keys.add(k);
                            }
                        }
                    }
                }
            }
        }

        if (keys.isEmpty()) {
            System.out.println("No valid keys provided. Exiting.");
            return;
        }

        System.out.println("Starting benchmark with " + keys.size() + " sub-tasks...");
        System.out.println();

        try {
            // We initialize a temporary AuditAutomator instance just to utilize its SSL setup and HttpClient
            AuditAutomator automator = new AuditAutomator(certAlias, jiraUrl, false);
            automator.initHttpClient();

            // Run Method A: Individual Queries (with Parallel Threads)
            System.out.println("Running Method A: Parallel Individual Requests (20 Threads)...");
            long startA = System.currentTimeMillis();
            runIndividualQueries(automator, keys, 20);
            long timeA = System.currentTimeMillis() - startA;
            System.out.println("Method A Completed in: " + timeA + " ms");
            System.out.println();

            // Run Method B: Bulk JQL Query (Single HTTP Request)
            System.out.println("Running Method B: Single Bulk JQL Search Request...");
            long startB = System.currentTimeMillis();
            runBulkQuery(automator, keys);
            long timeB = System.currentTimeMillis() - startB;
            System.out.println("Method B Completed in: " + timeB + " ms");
            System.out.println();

            // Print Timing Results Side-by-Side
            System.out.println("==================================================");
            System.out.println("                 BENCHMARK RESULTS                ");
            System.out.println("==================================================");
            System.out.println("Total Keys Queried: " + keys.size());
            System.out.println(String.format("Method A (Individual HTTP Calls):  %d ms (Avg: %.1f ms/key)", timeA, (double) timeA / keys.size()));
            System.out.println(String.format("Method B (Single Bulk JQL):        %d ms (Avg: %.1f ms/key)", timeB, (double) timeB / keys.size()));
            System.out.println("--------------------------------------------------");
            
            if (timeB < timeA) {
                double speedup = (double) timeA / timeB;
                double savings = ((double) (timeA - timeB) / timeA) * 100.0;
                System.out.println(String.format("Method B is %.2fx FASTER (%.1f%% time saved)!", speedup, savings));
            } else {
                System.out.println("Method A was faster or equal (possibly due to cache hit or small batch size).");
            }
            System.out.println("==================================================");

            automator.close();
        } catch (Exception e) {
            System.out.println("Benchmark failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void runIndividualQueries(AuditAutomator automator, List<String> keys, int poolSize) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(poolSize);
        List<Future<?>> futures = new ArrayList<>();

        for (final String key : keys) {
            futures.add(executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        String url = automator.getJiraUrl() + "/rest/api/2/issue/" + key;
                        // Avoid caching during benchmark to ensure we measure real network query speeds
                        String res = executeFreshGet(automator, url);
                        if (res != null) {
                            JsonObject payload = JsonParser.parseString(res).getAsJsonObject();
                            JsonObject fields = payload.getAsJsonObject("fields");
                            String summary = fields.get("summary") != null ? fields.get("summary").getAsString() : "";
                        }
                    } catch (Exception e) {
                        System.err.println("Failed query for " + key + ": " + e.getMessage());
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();
    }

    private static void runBulkQuery(AuditAutomator automator, List<String> keys) throws Exception {
        StringBuilder jql = new StringBuilder("key in (");
        for (int i = 0; i < keys.size(); i++) {
            jql.append(keys.get(i));
            if (i < keys.size() - 1) {
                jql.append(",");
            }
        }
        jql.append(")");

        String url = automator.getJiraUrl() + "/rest/api/2/search?jql=" + URLEncoder.encode(jql.toString(), "UTF-8") + "&fields=summary,description&maxResults=1000";
        String res = executeFreshGet(automator, url);
        if (res != null) {
            JsonObject response = JsonParser.parseString(res).getAsJsonObject();
            JsonArray issues = response.getAsJsonArray("issues");
            if (issues != null) {
                for (JsonElement el : issues) {
                    JsonObject issue = el.getAsJsonObject();
                    JsonObject fields = issue.getAsJsonObject("fields");
                    String summary = fields.get("summary") != null ? fields.get("summary").getAsString() : "";
                }
            }
        }
    }

    private static String executeFreshGet(AuditAutomator automator, String url) throws Exception {
        HttpGet request = new HttpGet(url);
        request.addHeader("Accept", "application/json");
        try (CloseableHttpResponse response = automator.getHttpClient().execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            if (status == 200) {
                HttpEntity entity = response.getEntity();
                return entity != null ? EntityUtils.toString(entity) : null;
            }
        }
        return null;
    }
}
