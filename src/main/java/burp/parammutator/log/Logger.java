package burp.parammutator.log;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class Logger extends AbstractTableModel {
    private static final String[] COLS = {
            "Level",
            "Origin",
            "Path",
            "DateTime",
            "Message"
    };

    private final List<LogEntry> entries = new ArrayList<>();
    private LogLevel logLevel = LogLevel.FULL;

    // Default 100MB
    private long maxSizeBytes = 100L * 1024 * 1024;
    private long currentSizeBytes = 0;

    private static final DateTimeFormatter DATETIMEFORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
                    .withZone(ZoneId.systemDefault());

    private static Logger instance;

    public static synchronized Logger getInstance() {
        if (instance == null) {
            instance = new Logger();
        }
        return instance;
    }

    private Logger() {
    }

    public void setLogLevel(LogLevel level) {
        this.logLevel = level;
        synchronized (this) {
            recalcCurrentSize();
            fireTableDataChanged();
        }
    }

    public LogLevel getLogLevel() {
        return logLevel;
    }

    public synchronized void log(LogLevel level, String origin, String path, String msg) {
        if (level.ordinal() < logLevel.ordinal()) {
            return;
        }

        LogEntry entry = new LogEntry(level, origin, path, Instant.now(), msg);

        long estimatedSize = estimateEntrySize(entry);

        while (currentSizeBytes + estimatedSize > maxSizeBytes && !entries.isEmpty()) {
            LogEntry removed = entries.remove(0);
            currentSizeBytes -= estimateEntrySize(removed);
        }

        entries.add(entry);
        currentSizeBytes += estimatedSize;

        fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
    }

    private void recalcCurrentSize() {
        currentSizeBytes = 0;
        for (LogEntry e : entries) {
            currentSizeBytes += estimateEntrySize(e);
        }
    }

    private long estimateEntrySize(LogEntry entry) {
        return (long) entry.level.name().length()
                + (entry.origin != null ? entry.origin.length() : 0)
                + (entry.path != null ? entry.path.length() : 0)
                + (entry.msg != null ? entry.msg.length() : 0)
                + 40;
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLS[column];
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry entry = entries.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> entry.level;
            case 1 -> entry.origin;
            case 2 -> entry.path;
            case 3 -> DATETIMEFORMAT.format(entry.timestamp);
            case 4 -> entry.msg;
            default -> null;
        };
    }

    public synchronized void clear() {
        entries.clear();
        currentSizeBytes = 0;
        fireTableDataChanged();
    }

    public synchronized long getMaxSizeBytes() {
        return maxSizeBytes;
    }

    public synchronized void setMaxSizeBytes(long maxSizeBytes) {
        this.maxSizeBytes = maxSizeBytes;

        Iterator<LogEntry> it = entries.iterator();
        while (currentSizeBytes > maxSizeBytes && it.hasNext()) {
            LogEntry removed = it.next();
            currentSizeBytes -= estimateEntrySize(removed);
            it.remove();
        }
        fireTableDataChanged();
    }

    public synchronized void logFullJson(String origin, String path, Map<String, String> paramValueMap) {
        if (logLevel != LogLevel.FULL) {
            return;
        }
        String json = toJson(paramValueMap);
        log(LogLevel.FULL, origin, path, json);
    }

    public synchronized void logInfoJson(String origin, String path, Map<String, String> changedParamValueMap) {
        if (logLevel != LogLevel.INFO) {
            return;
        }
        if (changedParamValueMap == null || changedParamValueMap.isEmpty()) {
            return;
        }
        String json = toJson(changedParamValueMap);
        log(LogLevel.INFO, origin, path, json);
    }

    private String toJson(Map<String, String> paramValueMap) {
        if (paramValueMap == null) {
            return "{}";
        }
        try {
            return paramValueMap.entrySet().stream()
                    .map(e -> String.format("\"%s\":\"%s\"",
                            escapeJson(e.getKey()),
                            escapeJson(e.getValue())))
                    .collect(Collectors.joining(",", "{", "}"));
        } catch (Exception ex) {
            return "{}";
        }
    }

    private String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    public static class LogEntry {
        final LogLevel level;
        final String origin;
        final String path;
        final Instant timestamp;
        final String msg;

        LogEntry(LogLevel level, String origin, String path, Instant timestamp, String msg) {
            this.level = level;
            this.origin = origin;
            this.path = path;
            this.timestamp = timestamp;
            this.msg = msg;
        }
    }
}
