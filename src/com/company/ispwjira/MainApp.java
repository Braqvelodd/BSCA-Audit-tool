package com.company.ispwjira;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.ComboBoxTableCell;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MainApp extends Application {

    public static class ObservableAuditRow {
        private final AuditAutomator.AuditRow original;
        
        // 19 Properties matching CSV fields
        private final SimpleStringProperty selected;
        private final SimpleStringProperty appl;
        private final SimpleStringProperty type;
        private final SimpleStringProperty name;
        private final SimpleStringProperty ver;
        private final SimpleStringProperty action;
        private final SimpleStringProperty releaseId;
        private final SimpleStringProperty date;
        private final SimpleStringProperty time;
        private final SimpleStringProperty path;
        private final SimpleStringProperty jiraNum;
        private final SimpleStringProperty workType;
        private final SimpleStringProperty test1;
        private final SimpleStringProperty test2;
        private final SimpleStringProperty test3;
        private final SimpleStringProperty test4;
        private final SimpleStringProperty test5;
        private final SimpleStringProperty test6;
        private final SimpleStringProperty notes;

        public ObservableAuditRow(AuditAutomator.AuditRow row) {
            this.original = row;
            this.selected = new SimpleStringProperty(row.selected);
            this.appl = new SimpleStringProperty(row.appl);
            this.type = new SimpleStringProperty(row.type);
            this.name = new SimpleStringProperty(row.name);
            this.ver = new SimpleStringProperty(row.ver);
            this.action = new SimpleStringProperty(row.action);
            this.releaseId = new SimpleStringProperty(row.releaseId);
            this.date = new SimpleStringProperty(row.date);
            this.time = new SimpleStringProperty(row.time);
            this.path = new SimpleStringProperty(row.path);
            this.jiraNum = new SimpleStringProperty(row.jiraNum);
            this.workType = new SimpleStringProperty(row.workType);
            this.test1 = new SimpleStringProperty(row.test1);
            this.test2 = new SimpleStringProperty(row.test2);
            this.test3 = new SimpleStringProperty(row.test3);
            this.test4 = new SimpleStringProperty(row.test4);
            this.test5 = new SimpleStringProperty(row.test5);
            this.test6 = new SimpleStringProperty(row.test6);
            this.notes = new SimpleStringProperty(row.notes);

            // Sync UI edits back to core entities
            this.selected.addListener((obs, oldVal, newVal) -> original.selected = newVal);
            this.appl.addListener((obs, oldVal, newVal) -> original.appl = newVal);
            this.type.addListener((obs, oldVal, newVal) -> original.type = newVal);
            this.name.addListener((obs, oldVal, newVal) -> original.name = newVal);
            this.ver.addListener((obs, oldVal, newVal) -> original.ver = newVal);
            this.action.addListener((obs, oldVal, newVal) -> original.action = newVal);
            this.releaseId.addListener((obs, oldVal, newVal) -> original.releaseId = newVal);
            this.date.addListener((obs, oldVal, newVal) -> original.date = newVal);
            this.time.addListener((obs, oldVal, newVal) -> original.time = newVal);
            this.path.addListener((obs, oldVal, newVal) -> original.path = newVal);
            this.jiraNum.addListener((obs, oldVal, newVal) -> original.jiraNum = newVal);
            this.workType.addListener((obs, oldVal, newVal) -> original.workType = newVal);
            this.test1.addListener((obs, oldVal, newVal) -> original.test1 = newVal);
            this.test2.addListener((obs, oldVal, newVal) -> original.test2 = newVal);
            this.test3.addListener((obs, oldVal, newVal) -> original.test3 = newVal);
            this.test4.addListener((obs, oldVal, newVal) -> original.test4 = newVal);
            this.test5.addListener((obs, oldVal, newVal) -> original.test5 = newVal);
            this.test6.addListener((obs, oldVal, newVal) -> original.test6 = newVal);
            this.notes.addListener((obs, oldVal, newVal) -> original.notes = newVal);
        }

        // Selected
        public String getSelected() { return selected.get(); }
        public void setSelected(String val) { selected.set(val); }
        public SimpleStringProperty selectedProperty() { return selected; }

        // Appl
        public String getAppl() { return appl.get(); }
        public SimpleStringProperty applProperty() { return appl; }

        // Type
        public String getType() { return type.get(); }
        public SimpleStringProperty typeProperty() { return type; }

        // Name
        public String getName() { return name.get(); }
        public SimpleStringProperty nameProperty() { return name; }

        // Ver
        public String getVer() { return ver.get(); }
        public SimpleStringProperty verProperty() { return ver; }

        // Action
        public String getAction() { return action.get(); }
        public SimpleStringProperty actionProperty() { return action; }

        // ReleaseId
        public String getReleaseId() { return releaseId.get(); }
        public SimpleStringProperty releaseIdProperty() { return releaseId; }

        // Date
        public String getDate() { return date.get(); }
        public SimpleStringProperty dateProperty() { return date; }

        // Time
        public String getTime() { return time.get(); }
        public SimpleStringProperty timeProperty() { return time; }

        // Path
        public String getPath() { return path.get(); }
        public SimpleStringProperty pathProperty() { return path; }

        // JiraNum
        public String getJiraNum() { return jiraNum.get(); }
        public void setJiraNum(String val) { jiraNum.set(val); }
        public SimpleStringProperty jiraNumProperty() { return jiraNum; }

        // WorkType
        public String getWorkType() { return workType.get(); }
        public void setWorkType(String val) { workType.set(val); }
        public SimpleStringProperty workTypeProperty() { return workType; }

        // Test1
        public String getTest1() { return test1.get(); }
        public void setTest1(String val) { test1.set(val); }
        public SimpleStringProperty test1Property() { return test1; }

        // Test2
        public String getTest2() { return test2.get(); }
        public void setTest2(String val) { test2.set(val); }
        public SimpleStringProperty test2Property() { return test2; }

        // Test3
        public String getTest3() { return test3.get(); }
        public void setTest3(String val) { test3.set(val); }
        public SimpleStringProperty test3Property() { return test3; }

        // Test4
        public String getTest4() { return test4.get(); }
        public void setTest4(String val) { test4.set(val); }
        public SimpleStringProperty test4Property() { return test4; }

        // Test5
        public String getTest5() { return test5.get(); }
        public void setTest5(String val) { test5.set(val); }
        public SimpleStringProperty test5Property() { return test5; }

        // Test6 (Manual check)
        public String getTest6() { return test6.get(); }
        public void setTest6(String val) { test6.set(val); }
        public SimpleStringProperty test6Property() { return test6; }

        // Notes
        public String getNotes() { return notes.get(); }
        public void setNotes(String val) { notes.set(val); }
        public SimpleStringProperty notesProperty() { return notes; }

        public AuditAutomator.AuditRow getOriginal() { return original; }
    }

    private final ObservableList<ObservableAuditRow> tableItems = FXCollections.observableArrayList();
    private TableView<ObservableAuditRow> tableView;

    private TextField jiraUrlField;
    private ComboBox<CertificateManager.CertInfo> certComboBox;
    private CheckBox traceLoggingCheckbox;
    private TextField inputPathField;
    private TextArea logArea;
    private Button runButton;
    private Button exportButton;
    private ProgressBar progressBar;

    private File selectedInputFile;
    private File selectedOutputFile;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("ISPW-Jira Compliance Audit Automator");

        // Thread-safe buffer for logs
        final java.util.Queue<String> logQueue = new java.util.concurrent.ConcurrentLinkedQueue<>();
        AuditLogger.setLogListener(entry -> logQueue.add(entry));

        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: #f1f5f9;");

        // Header Title
        VBox header = new VBox();
        header.setStyle("-fx-background-color: #1e293b; -fx-padding: 15px;");
        Label title = new Label("ISPW-JIRA AUDIT AUTOMATOR");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 20));
        title.setTextFill(Color.WHITE);
        Label subtitle = new Label("Compliance QA Audit Verification Engine (DoD CAC PKI)");
        subtitle.setFont(Font.font("Segoe UI", 12));
        subtitle.setTextFill(Color.LIGHTGRAY);
        header.getChildren().addAll(title, subtitle);
        root.setTop(header);

        // Top Section: Config Card + Table Card
        TitledPane configCard = createConfigCard();
        VBox tableCard = createTableCard();
        VBox topSection = new VBox(10, configCard, tableCard);
        VBox.setVgrow(tableCard, Priority.ALWAYS);
        topSection.setPadding(new Insets(10));

        // Bottom Section: Execution Console Logs + Progress Bar
        VBox bottomSection = new VBox(5);
        bottomSection.setPadding(new Insets(10));

        Label logLabel = new Label("Execution Console Logs:");
        logLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        logLabel.setTextFill(Color.web("#334155"));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setFont(Font.font("Consolas", 11));
        logArea.setStyle("-fx-control-inner-background: #0f172a; -fx-text-fill: #38bdf8;");
        VBox.setVgrow(logArea, Priority.ALWAYS);

        // Periodic log consumer in JavaFX thread (updates UI every 150ms)
        javafx.animation.Timeline logUpdater = new javafx.animation.Timeline(
            new javafx.animation.KeyFrame(javafx.util.Duration.millis(150), event -> {
                if (!logQueue.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = logQueue.poll()) != null) {
                        sb.append(line).append("\n");
                    }
                    logArea.appendText(sb.toString());
                    
                    int maxChars = 200000;
                    if (logArea.getLength() > maxChars) {
                        String currentText = logArea.getText();
                        logArea.setText("[... truncated oldest log history to maintain UI performance ...]\n" 
                                + currentText.substring(currentText.length() - 100000));
                    }
                    
                    logArea.setScrollTop(Double.MAX_VALUE);
                }
            })
        );
        logUpdater.setCycleCount(javafx.animation.Animation.INDEFINITE);
        logUpdater.play();

        progressBar = new ProgressBar(0);
        progressBar.setMaxWidth(Double.MAX_VALUE);
        progressBar.setVisible(false);

        bottomSection.getChildren().addAll(logLabel, logArea, progressBar);

        // Vertical SplitPane to allow user-adjustable scaling of table and logs
        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(javafx.geometry.Orientation.VERTICAL);
        splitPane.getItems().addAll(topSection, bottomSection);
        splitPane.setDividerPositions(0.70f); // 70% table, 30% logs

        root.setCenter(splitPane);

        loadConfigValues();

        Scene scene = new Scene(root, 1150, 780);

        // Support Drag & Drop of CSV files anywhere on the application window
        scene.setOnDragOver(event -> {
            if (event.getGestureSource() != scene && event.getDragboard().hasFiles()) {
                boolean hasCsv = false;
                for (File file : event.getDragboard().getFiles()) {
                    if (file.getName().toLowerCase().endsWith(".csv")) {
                        hasCsv = true;
                        break;
                    }
                }
                if (hasCsv) {
                    event.acceptTransferModes(TransferMode.COPY_OR_MOVE);
                }
            }
            event.consume();
        });

        scene.setOnDragDropped(event -> {
            Dragboard db = event.getDragboard();
            boolean success = false;
            if (db.hasFiles()) {
                File csvFile = null;
                for (File file : db.getFiles()) {
                    if (file.getName().toLowerCase().endsWith(".csv")) {
                        csvFile = file;
                        break;
                    }
                }
                if (csvFile != null) {
                    setInputFile(csvFile);
                    success = true;
                }
            }
            event.setDropCompleted(success);
            event.consume();
        });

        primaryStage.setScene(scene);
        primaryStage.show();

        AuditLogger.info("Application started successfully.");
    }

    private TitledPane createConfigCard() {
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(10));
        grid.setStyle("-fx-background-color: #ffffff; -fx-background-radius: 5px;");

        // Row 0: Jira URL
        Label jiraUrlLabel = new Label("Jira Server URL:");
        jiraUrlLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        jiraUrlField = new TextField();
        jiraUrlField.setPrefWidth(300);
        grid.add(jiraUrlLabel, 0, 0);
        grid.add(jiraUrlField, 1, 0);

        traceLoggingCheckbox = new CheckBox("Enable Detailed JIRA Trace Logging");
        traceLoggingCheckbox.setFont(Font.font("Segoe UI", 12));
        grid.add(traceLoggingCheckbox, 2, 0);
        traceLoggingCheckbox.selectedProperty().addListener((obs, oldVal, newVal) -> {
            ConfigManager.setTraceLoggingEnabled(newVal);
            ConfigManager.save();
        });

        // Row 1: CAC Certificate
        Label certLabel = new Label("CAC Cert Select:");
        certLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        certComboBox = new ComboBox<>();
        certComboBox.setPrefWidth(450);
        grid.add(certLabel, 0, 1);
        grid.add(certComboBox, 1, 1, 2, 1);

        // Row 2: Input CSV
        Label inputLabel = new Label("Input ISPW CSV:");
        inputLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        inputPathField = new TextField();
        inputPathField.setEditable(false);
        inputPathField.setPrefWidth(300);
        Button btnSelectInput = new Button("Browse...");
        btnSelectInput.setOnAction(e -> selectFile(true));
        HBox inputHBox = new HBox(8, inputPathField, btnSelectInput);
        grid.add(inputLabel, 0, 2);
        grid.add(inputHBox, 1, 2, 2, 1);

        TitledPane pane = new TitledPane("System Configurations & CAC Authentication", grid);
        pane.setCollapsible(false);
        pane.setFont(Font.font("Segoe UI", FontWeight.BOLD, 13));
        return pane;
    }

    private VBox createTableCard() {
        VBox card = new VBox(8);
        card.setPadding(new Insets(10));
        card.setStyle("-fx-background-color: #ffffff; -fx-background-radius: 5px; -fx-effect: dropshadow(three-pass-box, rgba(0,0,0,0.05), 5, 0, 0, 1);");

        Label tableTitle = new Label("Quarterly Compliance Matrix (Double-click status cells or Notes/Jira Key to manually edit)");
        tableTitle.setFont(Font.font("Segoe UI", FontWeight.BOLD, 13));
        tableTitle.setTextFill(Color.web("#1e293b"));

        // Table initialization
        tableView = new TableView<>();
        tableView.setEditable(true);
        tableView.setItems(tableItems);
        VBox.setVgrow(tableView, Priority.ALWAYS);

        // Define columns matching 19 columns in CSV
        TableColumn<ObservableAuditRow, String> colSelected = new TableColumn<>("Selected");
        colSelected.setCellValueFactory(d -> d.getValue().selectedProperty());
        colSelected.setCellFactory(ComboBoxTableCell.forTableColumn("Y", " "));
        colSelected.setOnEditCommit(e -> e.getRowValue().setSelected(e.getNewValue()));
        colSelected.setPrefWidth(70);

        TableColumn<ObservableAuditRow, String> colAppl = new TableColumn<>("APPL");
        colAppl.setCellValueFactory(d -> d.getValue().applProperty());
        colAppl.setPrefWidth(55);

        TableColumn<ObservableAuditRow, String> colType = new TableColumn<>("Type");
        colType.setCellValueFactory(d -> d.getValue().typeProperty());
        colType.setPrefWidth(55);

        TableColumn<ObservableAuditRow, String> colName = new TableColumn<>("Name");
        colName.setCellValueFactory(d -> d.getValue().nameProperty());
        colName.setPrefWidth(85);

        TableColumn<ObservableAuditRow, String> colVer = new TableColumn<>("Ver");
        colVer.setCellValueFactory(d -> d.getValue().verProperty());
        colVer.setPrefWidth(45);

        TableColumn<ObservableAuditRow, String> colAction = new TableColumn<>("Action");
        colAction.setCellValueFactory(d -> d.getValue().actionProperty());
        colAction.setPrefWidth(50);

        TableColumn<ObservableAuditRow, String> colRelease = new TableColumn<>("Release ID");
        colRelease.setCellValueFactory(d -> d.getValue().releaseIdProperty());
        colRelease.setPrefWidth(90);

        TableColumn<ObservableAuditRow, String> colDate = new TableColumn<>("Date");
        colDate.setCellValueFactory(d -> d.getValue().dateProperty());
        colDate.setPrefWidth(80);

        TableColumn<ObservableAuditRow, String> colTime = new TableColumn<>("Time");
        colTime.setCellValueFactory(d -> d.getValue().timeProperty());
        colTime.setPrefWidth(70);

        TableColumn<ObservableAuditRow, String> colPath = new TableColumn<>("Path");
        colPath.setCellValueFactory(d -> d.getValue().pathProperty());
        colPath.setPrefWidth(50);

        // Jira columns
        TableColumn<ObservableAuditRow, String> colEpic = new TableColumn<>("Jira Epic Key");
        colEpic.setCellValueFactory(d -> d.getValue().jiraNumProperty());
        colEpic.setCellFactory(TextFieldTableCell.forTableColumn());
        colEpic.setOnEditCommit(e -> e.getRowValue().setJiraNum(e.getNewValue()));
        colEpic.setPrefWidth(90);

        TableColumn<ObservableAuditRow, String> colWorkType = new TableColumn<>("Work Type");
        colWorkType.setCellValueFactory(d -> d.getValue().workTypeProperty());
        colWorkType.setCellFactory(TextFieldTableCell.forTableColumn());
        colWorkType.setOnEditCommit(e -> e.getRowValue().setWorkType(e.getNewValue()));
        colWorkType.setPrefWidth(85);

        // Tests 1 to 5
        TableColumn<ObservableAuditRow, String> colTest1 = createEditableStatusColumn("TEST 1\n(Work Type)", "test1");
        TableColumn<ObservableAuditRow, String> colTest2 = createEditableStatusColumn("TEST 2\n(Approved)", "test2");
        TableColumn<ObservableAuditRow, String> colTest3 = createEditableStatusColumn("TEST 3\n(Evidence)", "test3");
        TableColumn<ObservableAuditRow, String> colTest4 = createEditableStatusColumn("TEST 4\n(QA Status)", "test4");
        TableColumn<ObservableAuditRow, String> colTest5 = createEditableStatusColumn("TEST 5\n(Released)", "test5");
        
        // TEST 6: 100% manual check
        TableColumn<ObservableAuditRow, String> colTest6 = createEditableStatusColumn("TEST 6\n(Manual)", "test6");

        // Notes Column
        TableColumn<ObservableAuditRow, String> colNotes = new TableColumn<>("Audit Notes");
        colNotes.setCellValueFactory(d -> d.getValue().notesProperty());
        colNotes.setCellFactory(TextFieldTableCell.forTableColumn());
        colNotes.setOnEditCommit(e -> e.getRowValue().setNotes(e.getNewValue()));
        colNotes.setPrefWidth(150);

        tableView.getColumns().addAll(
                colSelected, colAppl, colType, colName, colVer, colAction, colRelease, colDate, colTime, colPath,
                colEpic, colWorkType, colTest1, colTest2, colTest3, colTest4, colTest5, colTest6, colNotes
        );

        // Run/Export Buttons
        runButton = new Button("Run Audit Pipeline");
        runButton.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        runButton.setStyle("-fx-background-color: #2563eb; -fx-text-fill: white; -fx-padding: 8px 16px; -fx-background-radius: 4px;");
        runButton.setOnAction(e -> handleRunAudit());

        exportButton = new Button("Export Reports (CSV)");
        exportButton.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        exportButton.setStyle("-fx-background-color: #16a34a; -fx-text-fill: white; -fx-padding: 8px 16px; -fx-background-radius: 4px;");
        exportButton.setOnAction(e -> handleExportCsv());
        exportButton.setDisable(true);

        HBox btnHBox = new HBox(12, runButton, exportButton);
        btnHBox.setAlignment(Pos.CENTER_RIGHT);

        card.getChildren().addAll(tableTitle, tableView, btnHBox);
        return card;
    }

    private TableColumn<ObservableAuditRow, String> createEditableStatusColumn(String title, String propertyName) {
        TableColumn<ObservableAuditRow, String> column = new TableColumn<>(title);
        column.setPrefWidth(90);

        if ("test1".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test1Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest1(e.getNewValue()));
        } else if ("test2".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test2Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest2(e.getNewValue()));
        } else if ("test3".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test3Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest3(e.getNewValue()));
        } else if ("test4".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test4Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest4(e.getNewValue()));
        } else if ("test5".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test5Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest5(e.getNewValue()));
        } else if ("test6".equals(propertyName)) {
            column.setCellValueFactory(d -> d.getValue().test6Property());
            column.setOnEditCommit(e -> e.getRowValue().setTest6(e.getNewValue()));
        }

        // Style status colors
        column.setCellFactory(col -> new ComboBoxTableCell<ObservableAuditRow, String>("Y", "N", "REVIEW") {
            @Override
            public void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    if ("Y".equalsIgnoreCase(item)) {
                        setStyle("-fx-background-color: #d4edda; -fx-text-fill: #155724; -fx-alignment: center; -fx-font-weight: bold;");
                    } else if ("N".equalsIgnoreCase(item)) {
                        setStyle("-fx-background-color: #f8d7da; -fx-text-fill: #721c24; -fx-alignment: center; -fx-font-weight: bold;");
                    } else if ("REVIEW".equalsIgnoreCase(item)) {
                        setStyle("-fx-background-color: #fff3cd; -fx-text-fill: #856404; -fx-alignment: center; -fx-font-weight: bold;");
                    } else {
                        setStyle("-fx-alignment: center;");
                    }
                }
            }
        });

        return column;
    }

    private void loadConfigValues() {
        jiraUrlField.setText(ConfigManager.getJiraUrl());
        traceLoggingCheckbox.setSelected(ConfigManager.isTraceLoggingEnabled());
        refreshCertificateList();

        String lastCert = ConfigManager.getLastSelectedCert();
        if (!lastCert.isEmpty()) {
            for (CertificateManager.CertInfo info : certComboBox.getItems()) {
                if (info.getAlias().equals(lastCert)) {
                    certComboBox.setValue(info);
                    break;
                }
            }
        }
    }

    private void refreshCertificateList() {
        List<CertificateManager.CertInfo> certs = CertificateManager.getAvailableCertificates();
        certComboBox.getItems().clear();
        certComboBox.getItems().addAll(certs);
        if (!certs.isEmpty()) {
            certComboBox.setValue(certs.get(0));
        }
    }

    private void setInputFile(File file) {
        if (file != null) {
            selectedInputFile = file;
            inputPathField.setText(file.getAbsolutePath());
            AuditLogger.info("Input file selected: " + file.getName());
            
            // Auto-generate output file name in same parent directory
            String parent = file.getParent();
            String name = file.getName();
            String base = name;
            String ext = ".csv";
            int lastDot = name.lastIndexOf('.');
            if (lastDot > 0) {
                base = name.substring(0, lastDot);
                ext = name.substring(lastDot);
            }
            selectedOutputFile = new File(parent, base + "_filled" + ext);
            AuditLogger.info("Auto-assigned output file: " + selectedOutputFile.getName());
        }
    }

    private void selectFile(boolean isInput) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files (*.csv)", "*.csv"));
        
        if (isInput) {
            fileChooser.setTitle("Open Input ISPW CSV Export File");
            File file = fileChooser.showOpenDialog(null);
            setInputFile(file);
        }
    }

    private void handleRunAudit() {
        String jiraUrl = jiraUrlField.getText().trim();
        CertificateManager.CertInfo selectedCert = certComboBox.getValue();
        boolean traceLogging = traceLoggingCheckbox.isSelected();

        if (jiraUrl.isEmpty()) {
            showAlert("Configuration Error", "Please provide a valid Jira Server URL.");
            return;
        }
        if (selectedInputFile == null || !selectedInputFile.exists()) {
            showAlert("Input Error", "Please select a valid input ISPW CSV file.");
            return;
        }
        if (selectedOutputFile == null) {
            showAlert("Output Error", "Please select a valid output audit CSV destination file.");
            return;
        }
        if (selectedCert == null) {
            showAlert("CAC Error", "A valid DoD CAC client certificate must be selected.");
            return;
        }

        ConfigManager.setJiraUrl(jiraUrl);
        ConfigManager.setTraceLoggingEnabled(traceLogging);
        if (selectedCert != null) {
            ConfigManager.setLastSelectedCert(selectedCert.getAlias());
        }
        ConfigManager.save();

        runButton.setDisable(true);
        exportButton.setDisable(true);
        progressBar.setVisible(true);
        progressBar.setProgress(-1);

        String alias = selectedCert != null ? selectedCert.getAlias() : "";
        
        Task<List<AuditAutomator.AuditRow>> auditTask = new Task<List<AuditAutomator.AuditRow>>() {
            @Override
            protected List<AuditAutomator.AuditRow> call() throws Exception {
                AuditLogger.resetLogFile();
                AuditLogger.info("Parsing 19-column input ISPW CSV...");
                List<AuditAutomator.AuditRow> rows = AuditAutomator.parseCsvReport(selectedInputFile);
                
                AuditAutomator automator = new AuditAutomator(alias, jiraUrl, traceLogging);
                try {
                    automator.initHttpClient();
                    automator.runAudit(rows);
                } finally {
                    automator.close();
                }
                return rows;
            }
        };

        auditTask.setOnSucceeded(e -> {
            try {
                List<AuditAutomator.AuditRow> resultRows = auditTask.getValue();
                List<ObservableAuditRow> temp = new ArrayList<>();
                for (AuditAutomator.AuditRow r : resultRows) {
                    temp.add(new ObservableAuditRow(r));
                }
                tableItems.setAll(temp);
                
                runButton.setDisable(false);
                exportButton.setDisable(false);
                progressBar.setVisible(false);
                AuditLogger.info("Audit verification process finished. Results populated in grid.");
            } catch (Exception ex) {
                AuditLogger.error("Failed to populate UI table: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        auditTask.setOnFailed(e -> {
            runButton.setDisable(false);
            progressBar.setVisible(false);
            Throwable err = auditTask.getException();
            AuditLogger.error("Audit run failed: " + err.getMessage());
            showAlert("Execution Error", "Audit run encountered an error: " + err.getMessage());
        });

        Thread thread = new Thread(auditTask);
        thread.setDaemon(true);
        thread.start();
    }

    private void handleExportCsv() {
        if (selectedOutputFile == null) {
            showAlert("Error", "No output file selected.");
            return;
        }
        
        try {
            List<AuditAutomator.AuditRow> rowsToSave = new ArrayList<>();
            for (ObservableAuditRow obsRow : tableItems) {
                rowsToSave.add(obsRow.getOriginal());
            }
            AuditAutomator.writeCsvReport(selectedOutputFile, rowsToSave);
            AuditLogger.info("Successfully exported 19-column compliance results to " + selectedOutputFile.getName());
            showInfoAlert("Export Success", "Compliance report successfully saved:\n" + selectedOutputFile.getAbsolutePath());
        } catch (Exception ex) {
            AuditLogger.error("Failed to export CSV: " + ex.getMessage());
            showAlert("Export Error", "Failed to write audit CSV: " + ex.getMessage());
        }
    }

    private void showAlert(String title, String content) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }

    private void showInfoAlert(String title, String content) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }
}
