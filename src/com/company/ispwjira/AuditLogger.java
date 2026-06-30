package com.company.ispwjira;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class AuditLogger {
    private static final String LOG_FILE = "audit.log";
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public interface LogListener {
        void onLog(String entry);
    }

    private static LogListener logListener;

    public static synchronized void setLogListener(LogListener listener) {
        logListener = listener;
    }

    public enum Level {
        INFO, WARN, ERROR, FATAL
    }

    public static synchronized void log(Level level, String message) {
        String timestamp = DATE_FORMAT.format(new Date());
        String logEntry = String.format("[%s] [%s] %s", timestamp, level, message);

        // Print to standard output/error
        if (level == Level.ERROR || level == Level.FATAL) {
            System.err.println(logEntry);
        } else {
            System.out.println(logEntry);
        }

        // Notify listener if registered
        if (logListener != null) {
            logListener.onLog(logEntry);
        }

        // Append to audit.log
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Failed to write to " + LOG_FILE + ": " + e.getMessage());
        }
    }

    public static void info(String message) {
        log(Level.INFO, message);
    }

    public static void warn(String message) {
        log(Level.WARN, message);
    }

    public static void error(String message) {
        log(Level.ERROR, message);
    }

    public static void fatal(String message) {
        log(Level.FATAL, message);
    }
}
