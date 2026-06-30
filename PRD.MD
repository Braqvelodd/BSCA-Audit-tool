# Product Requirements Document: ISPW-Jira Audit Automator

**Objective:** Automate the quarterly QA audit process by parsing ISPW release reports, bridging the data to Jira Epics via JQL search, and validating six specific compliance rules to generate an automated pass/fail matrix.
 

## Technical Specifications
 

| Requirement Type | Specification |

|---|---|
| **Runtime Environment** | Java 8 (JRE 1.8) |
| **User Interface** | Graphical User Interface (GUI) JavaFX |
| **Authentication (Client)** | DoD CAC PKI (Client Certificate via Windows-MY or SunPKCS11) |
| **Authentication (Server)** | **[DEV ONLY]** "Trust All" SSL Context (Ignores server certificate validation) |
| **HTTP Client** | Apache HttpClient (Required for building custom TrustManager/SSLContext) |
| **JSON Parser** | Google Gson or FasterXML Jackson |
| **Input Format** | CSV (Exported from the raw ISPW report) |
| **Output Format** | CSV (Appended with `TEST 1` through `TEST 6` results) |
 

## Core Application Workflow
 

The GUI application must execute the following sequential pipeline for each execution:

 
| Step | Action | Description |

|---|---|---|

| **1. Initialization** | Handle Windows-MY connections to JIRA URL stored in config.ini using Authentication Certs| The URL for JIRA must be stored in a config.ini. |
| **2. Ingestion** | Read ISPW data | Read the input CSV. Extract the `RELEASE` ID (e.g., `PTR0003156`) from each row. |
| **3. Resolution** | JQL Search | Query Jira via REST API: `project = TFS AND comment ~ "[RELEASE_ID]"`. Extract the matching Jira Epic Key (e.g., `TFS-1234`). |
| **4. Interrogation** | Fetch Epic & Sub-tasks | Query Jira via REST API to pull the full Epic JSON payload, including changelog and linked sub-tasks. |
| **5. Evaluation** | Run Audit Logic | Pass the JSON payload through the six audit validation tests. |
| **6. Display** | display ISPW data table in display with evaluation results | This results should allow the user to change and update them, while also being used to highlight any automation issues found |
| **6. Output** | Generate Report | Write the original row data plus `Y` or `N` values for `TEST 1` through `TEST 6` to the designated output CSV. |
 

## Audit Logic Definitions
 

The application must implement the following logical checks against the Jira JSON data for the located `TFS-\*` Epic.
 

| Audit Item | Business Rule | Technical Verification (Jira API) |
|---|---|---|
| **TEST 1** | Documented under valid work type. | Verify `fields.issuetype.name` matches authorized types (e.g., Epic, Story). |
| **TEST 2** | Proper authorization documented. | Verify `fields.status.name` indicates approval OR a specific authorization custom field is populated. |
| **TEST 3** | Evidence in Sub-Task. | Iterate `fields.subtasks`. Secondary query to sub-tasks to verify `fields.attachment` size > 0 OR comments exist. |
| **TEST 4** | Test performed and accepted. | Locate QA/Testing sub-task. Verify `fields.status.name` equals "Passed", "Accepted", or "Done". |
| **TEST 5** | Project approved for release. | Verify `fields.fixVersions[0].released` == `true` OR check parent project status. |
 

## Error Handling & Edge Cases

 
If X, do Y. This application must fail gracefully to ensure the quarterly audit is never corrupted by a runtime crash.
 

| Scenario | Application Behavior |
|---|---|
| **JQL returns 0 results** | Mark all tests as `N` (Fail). Log "No linked Jira Epic found for Release ID." |
| **JQL returns > 1 result** | Mark all tests as `REVIEW`. Log "Multiple Jira Epics mention this Release ID. Human review required." |
| **Jira API Rate Limit (HTTP 429)** | Pause execution. Read the `Retry-After` HTTP header, wait the specified seconds, and retry the request. |
| **Missing Data in Issue JSON** | If a field required for a test is null/missing, mark that specific test as `N` (Fail). Do not throw a NullPointerException. |
| **CAC Certificate Missing** | Abort execution. Log "FATAL: Valid DoD PKI certificate not found in keystore." |