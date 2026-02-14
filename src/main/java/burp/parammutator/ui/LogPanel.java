package burp.parammutator.ui;

import burp.api.montoya.MontoyaApi;
import burp.parammutator.log.Logger;
import burp.parammutator.log.LogLevel;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.FileWriter;
import java.io.IOException;

public class LogPanel extends JPanel {
    private final Logger logger = Logger.getInstance();
    private final MontoyaApi api;

    public LogPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());
        JTable table = new JTable(logger);
        table.setFillsViewportHeight(true);

        table.setAutoCreateRowSorter(true);
        TableRowSorter<Logger> sorter = new TableRowSorter<>(logger);
        table.setRowSorter(sorter);

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JComboBox<LogLevel> levelSelect = new JComboBox<>(LogLevel.values());
        levelSelect.setSelectedItem(logger.getLogLevel());
        controls.add(new JLabel("Log level: "));
        controls.add(levelSelect);

        JButton clearBtn = new JButton("Clear");
        controls.add(clearBtn);

        controls.add(new JLabel("Max log size (MB): "));
        JTextField maxSizeField = new JTextField(String.valueOf(logger.getMaxSizeBytes() / (1024 * 1024)), 5);
        controls.add(maxSizeField);

        JButton applyMaxSizeBtn = new JButton("Apply");
        controls.add(applyMaxSizeBtn);

        JButton saveCsvBtn = new JButton("Save as CSV");
        controls.add(saveCsvBtn);

        add(controls, BorderLayout.NORTH);

        levelSelect.addActionListener(e -> {
            LogLevel level = (LogLevel) levelSelect.getSelectedItem();
            logger.setLogLevel(level);
        });

        clearBtn.addActionListener(e -> logger.clear());

        applyMaxSizeBtn.addActionListener(e -> {
            try {
                int mb = Integer.parseInt(maxSizeField.getText().trim());
                if (mb > 0) {
                    logger.setMaxSizeBytes(mb * 1024L * 1024L);
                } else {
                    JOptionPane.showMessageDialog(
                        api.userInterface().swingUtils().suiteFrame(),
                        "Max size must be positive integer (MB)"
                    );
                }
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Invalid number format for max size"
                );
            }
        });

        saveCsvBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save Logs as CSV");
            fileChooser.setFileFilter(new FileNameExtensionFilter("CSV Files", "csv"));
            int userSelection = fileChooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                if (!filePath.toLowerCase().endsWith(".csv")) {
                    filePath += ".csv";
                }
                try (FileWriter csvWriter = new FileWriter(filePath)) {
                    for (int col = 0; col < logger.getColumnCount(); col++) {
                        csvWriter.append(logger.getColumnName(col));
                        if (col < logger.getColumnCount() - 1) csvWriter.append(',');
                    }
                    csvWriter.append('\n');
                    for (int row = 0; row < logger.getRowCount(); row++) {
                        for (int col = 0; col < logger.getColumnCount(); col++) {
                            Object val = logger.getValueAt(row, col);
                            String cell = val == null ? "" : val.toString().replace("\"", "\\\"");
                            csvWriter.append('"').append(cell).append('"');
                            if (col < logger.getColumnCount() - 1) csvWriter.append(',');
                        }
                        csvWriter.append('\n');
                    }
                    JOptionPane.showMessageDialog(
                        api.userInterface().swingUtils().suiteFrame(),
                        "Logs saved to CSV successfully."
                    );
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(
                        api.userInterface().swingUtils().suiteFrame(),
                        "Error saving CSV: " + ex.getMessage()
                    );
                }
            }
        });
    }
}
