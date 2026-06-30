package com.company.ispwjira;

import java.util.HashMap;
import java.util.Map;

public class MockJiraServer {

    private static int rateLimitHits = 0;

    public static class MockResponse {
        public final int statusCode;
        public final String body;
        public final Map<String, String> headers;

        public MockResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = new HashMap<>();
        }

        public MockResponse(int statusCode, String body, Map<String, String> headers) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = headers;
        }
    }

    public static MockResponse handleRequest(String url) {
        AuditLogger.info("[MOCK SERVER] Intercepted request to: " + url);

        // Simulate Rate Limiting for PTR0004290
        if (url.contains("PTR0004290") && rateLimitHits < 1) {
            rateLimitHits++;
            Map<String, String> headers = new HashMap<>();
            headers.put("Retry-After", "2");
            AuditLogger.warn("[MOCK SERVER] Simulating 429 Rate Limit. Retry-After: 2s");
            return new MockResponse(429, "Too Many Requests", headers);
        }

        // 1. JQL Searches
        if (url.contains("/rest/api/2/search")) {
            if (url.contains("PTR0003156") || url.contains("PTR0004290")) {
                // Normal epic
                return new MockResponse(200, getJqlResponse("TFS-1234"));
            } else if (url.contains("PTR0000000")) {
                // Zero epics
                return new MockResponse(200, getEmptyJqlResponse());
            } else if (url.contains("PTR0009999")) {
                // Multiple epics
                return new MockResponse(200, getMultipleJqlResponse("TFS-8888", "TFS-9999"));
            } else if (url.contains("PTR0001111")) {
                // Failed epic tests
                return new MockResponse(200, getJqlResponse("TFS-2222"));
            } else {
                // Default fallback to normal
                return new MockResponse(200, getJqlResponse("TFS-1234"));
            }
        }

        // 2. Fetch Epic Details
        if (url.contains("/rest/api/2/issue/TFS-1234")) {
            return new MockResponse(200, getNormalEpicJson());
        } else if (url.contains("/rest/api/2/issue/TFS-2222")) {
            return new MockResponse(200, getFailedEpicJson());
        }

        // 3. Fetch Sub-tasks details for TEST 3 validation (e.g., check attachment size or comments)
        if (url.contains("/rest/api/2/issue/TFS-1235")) {
            // QA sub-task (valid)
            return new MockResponse(200, getSubTaskJson("TFS-1235", "QA/Testing", "Passed", true));
        } else if (url.contains("/rest/api/2/issue/TFS-1236")) {
            // Dev subtask (valid)
            return new MockResponse(200, getSubTaskJson("TFS-1236", "Development", "Done", false));
        } else if (url.contains("/rest/api/2/issue/TFS-2225")) {
            // QA subtask for TFS-2222 (failed)
            return new MockResponse(200, getSubTaskJson("TFS-2225", "QA/Testing", "In Progress", false));
        }

        return new MockResponse(404, "{\"errorMessages\":[\"Not Found\"],\"errors\":{}}");
    }

    private static String getJqlResponse(String key) {
        return "{\n" +
                "  \"startAt\": 0,\n" +
                "  \"maxResults\": 50,\n" +
                "  \"total\": 1,\n" +
                "  \"issues\": [\n" +
                "    {\n" +
                "      \"key\": \"" + key + "\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }

    private static String getEmptyJqlResponse() {
        return "{\n" +
                "  \"startAt\": 0,\n" +
                "  \"maxResults\": 50,\n" +
                "  \"total\": 0,\n" +
                "  \"issues\": []\n" +
                "}";
    }

    private static String getMultipleJqlResponse(String key1, String key2) {
        return "{\n" +
                "  \"startAt\": 0,\n" +
                "  \"maxResults\": 50,\n" +
                "  \"total\": 2,\n" +
                "  \"issues\": [\n" +
                "    { \"key\": \"" + key1 + "\" },\n" +
                "    { \"key\": \"" + key2 + "\" }\n" +
                "  ]\n" +
                "}";
    }

    private static String getNormalEpicJson() {
        return "{\n" +
                "  \"key\": \"TFS-1234\",\n" +
                "  \"fields\": {\n" +
                "    \"issuetype\": { \"name\": \"Epic\" },\n" +
                "    \"status\": { \"name\": \"Approved\" },\n" +
                "    \"subtasks\": [\n" +
                "      { \"key\": \"TFS-1235\" },\n" +
                "      { \"key\": \"TFS-1236\" }\n" +
                "    ],\n" +
                "    \"fixVersions\": [\n" +
                "      { \"name\": \"v1.0\", \"released\": true }\n" +
                "    ]\n" +
                "  }\n" +
                "}";
    }

    private static String getFailedEpicJson() {
        return "{\n" +
                "  \"key\": \"TFS-2222\",\n" +
                "  \"fields\": {\n" +
                "    \"issuetype\": { \"name\": \"Story\" },\n" + // Story is allowed in test 1
                "    \"status\": { \"name\": \"In Progress\" },\n" + // TEST 2 Fail (Not Approved)
                "    \"subtasks\": [\n" +
                "      { \"key\": \"TFS-2225\" }\n" +
                "    ],\n" +
                "    \"fixVersions\": []\n" + // TEST 5 Fail (No fix versions or unreleased)
                "  }\n" +
                "}";
    }

    private static String getSubTaskJson(String key, String typeName, String statusName, boolean hasAttachments) {
        String attachmentJson = hasAttachments ? "[{ \"id\": \"999\", \"size\": 1024 }]" : "[]";
        return "{\n" +
                "  \"key\": \"" + key + "\",\n" +
                "  \"fields\": {\n" +
                "    \"summary\": \"" + typeName + "\",\n" +
                "    \"issuetype\": { \"name\": \"Sub-task\" },\n" +
                "    \"status\": { \"name\": \"" + statusName + "\" },\n" +
                "    \"attachment\": " + attachmentJson + ",\n" +
                "    \"comment\": {\n" +
                "      \"comments\": [\n" +
                "        { \"body\": \"Looks good!\" }\n" +
                "      ]\n" +
                "    }\n" +
                "  }\n" +
                "}";
    }
}
