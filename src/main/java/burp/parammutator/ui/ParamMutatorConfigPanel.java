package burp.parammutator.ui;

import burp.parammutator.log.Logger;
import burp.parammutator.model.*;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.plaf.basic.BasicTableHeaderUI;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

public class ParamMutatorConfigPanel extends JPanel {

    private static final int MAX_RULES = 100;

    public interface ConfigListener {
        void onConfigChanged(ExtensionConfig config);
    }

    private final JCheckBox enabledCheck = new JCheckBox("Enable Param Mutator", false);

    private final RuleTableModel model = new RuleTableModel(MAX_RULES);
    private final JTable table = new JTable(model) {
        @Override
        protected JTableHeader createDefaultTableHeader() {
            return new GroupableTableHeader(getColumnModel());
        }
    };

    public ParamMutatorConfigPanel(ConfigListener listener) {
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(enabledCheck);

        topPanel.add(new JLabel("Number of rules:"));
        JSpinner ruleCountSpinner = new JSpinner(new SpinnerNumberModel(15, 1, MAX_RULES, 1));
        topPanel.add(ruleCountSpinner);

        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> {
            Logger logger = Logger.getInstance();

            List<ParamMutatorRule> rules = new ArrayList<>();
            for (int r = 0; r < model.getVisibleRowCount(); r++) {
                RuleRow row = model.rows.get(r);

                String pat = row.paramPattern == null ? "" : row.paramPattern.trim();
                if (pat.isEmpty()) continue;

                List<CodecOp> dec = new ArrayList<>();
                dec.add(row.dec1);
                dec.add(row.dec2);
                dec.add(row.dec3);
                dec.add(row.dec4);
                dec.removeIf(v -> v == null);

                List<CodecOp> enc = new ArrayList<>();
                enc.add(row.enc1);
                enc.add(row.enc2);
                enc.add(row.enc3);
                enc.add(row.enc4);
                enc.removeIf(v -> v == null);

                ParamMutatorRule rule = new ParamMutatorRule(
                        pat,
                        row.paramType,
                        row.mode,
                        row.randType,
                        row.position,
                        row.length,
                        row.text,
                        dec,
                        enc,
                        row.pathEnabled,
                        row.pathPattern,
                        row.pathRegex
                );
                rules.add(rule);
            }

            listener.onConfigChanged(new ExtensionConfig(rules, enabledCheck.isSelected()));
        });
        topPanel.add(apply);

        add(topPanel, BorderLayout.NORTH);

        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(24);

        installEditorsAndRenderers(table);

        JScrollPane sp = new JScrollPane(table);
        add(sp, BorderLayout.CENTER);

        GroupableTableHeader gh = (GroupableTableHeader) table.getTableHeader();
        setupGroupedHeader(gh);
        sp.setColumnHeaderView(gh);

        gh.revalidate();
        gh.repaint();

        model.addTableModelListener(e -> {
            if (e.getType() == TableModelEvent.UPDATE) {
                table.repaint();
            }
        });

        ruleCountSpinner.addChangeListener(e ->
                model.setVisibleRowCount((Integer) ruleCountSpinner.getValue())
        );
    }

    @Override
    public void addNotify() {
        super.addNotify();

        JTableHeader th = table.getTableHeader();

        if (!(th instanceof GroupableTableHeader)) {
            GroupableTableHeader gh = new GroupableTableHeader(table.getColumnModel());
            table.setTableHeader(gh);
            th = gh;
        }

        GroupableTableHeader gh = (GroupableTableHeader) th;

        gh.setUI(new GroupableTableHeaderUI());

        GroupableTableHeader rebuilt = new GroupableTableHeader(table.getColumnModel());
        rebuilt.setUI(new GroupableTableHeaderUI());
        setupGroupedHeader(rebuilt);
        table.setTableHeader(rebuilt);

        Container p = SwingUtilities.getAncestorOfClass(JScrollPane.class, table);
        if (p instanceof JScrollPane scroll) {
            scroll.setColumnHeaderView(rebuilt);
        }

        rebuilt.revalidate();
        rebuilt.repaint();
    }

    // -------------------- JTable columns --------------------

    private enum Col {
        PARAM_PATTERN("Parameter", String.class),
        // changed from Boolean "Is regex?" to enum Type
        PARAM_TYPE("Type", ParamMutatorRule.ParamPatternType.class),

        PATH_ENABLED("On?", Boolean.class),
        PATH_PATTERN("Path", String.class),
        PATH_REGEX("Is regex?", Boolean.class),

        MODE("Mode", MutationMode.class),
        TYPE("Random type", RandomType.class),
        TEXT("Text", String.class),
        POS("Pos", Position.class),
        LEN("Len", Integer.class),

        DEC1("Dec1", CodecOp.class),
        DEC2("Dec2", CodecOp.class),
        DEC3("Dec3", CodecOp.class),
        DEC4("Dec4", CodecOp.class),

        ENC1("Enc1", CodecOp.class),
        ENC2("Enc2", CodecOp.class),
        ENC3("Enc3", CodecOp.class),
        ENC4("Enc4", CodecOp.class);

        final String header;
        final Class<?> cls;

        Col(String header, Class<?> cls) {
            this.header = header;
            this.cls = cls;
        }
    }

    private static void installEditorsAndRenderers(JTable table) {
        TableColumnModel cm = table.getColumnModel();

        cm.getColumn(Col.MODE.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(MutationMode.values())));
        cm.getColumn(Col.TYPE.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(RandomType.values())));
        cm.getColumn(Col.POS.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(Position.values())));
        cm.getColumn(Col.PARAM_TYPE.ordinal()).setCellEditor(
                new DefaultCellEditor(new JComboBox<>(ParamMutatorRule.ParamPatternType.values()))
        );

        CodecOp[] decodeOps = {
                CodecOp.NO_OP,
                CodecOp.URL_DECODE,
                CodecOp.BASE64_DECODE,
                CodecOp.UNICODE_DECODE,
                CodecOp.UPPERCASE,
                CodecOp.LOWERCASE
        };
        CodecOp[] encodeOps = {
                CodecOp.NO_OP,
                CodecOp.URL_ENCODE,
                CodecOp.BASE64_ENCODE,
                CodecOp.UNICODE_ENCODE,
                CodecOp.UPPERCASE,
                CodecOp.LOWERCASE
        };

        cm.getColumn(Col.DEC1.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(decodeOps)));
        cm.getColumn(Col.DEC2.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(decodeOps)));
        cm.getColumn(Col.DEC3.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(decodeOps)));
        cm.getColumn(Col.DEC4.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(decodeOps)));

        cm.getColumn(Col.ENC1.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(encodeOps)));
        cm.getColumn(Col.ENC2.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(encodeOps)));
        cm.getColumn(Col.ENC3.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(encodeOps)));
        cm.getColumn(Col.ENC4.ordinal()).setCellEditor(new DefaultCellEditor(new JComboBox<>(encodeOps)));

        cm.getColumn(Col.LEN.ordinal()).setCellEditor(new IntegerCellEditor(1, 9999));

        setWidth(cm.getColumn(Col.PARAM_PATTERN.ordinal()), 180);
        setWidth(cm.getColumn(Col.PARAM_TYPE.ordinal()), 80);

        setWidth(cm.getColumn(Col.PATH_ENABLED.ordinal()), 55);
        setWidth(cm.getColumn(Col.PATH_PATTERN.ordinal()), 220);
        setWidth(cm.getColumn(Col.PATH_REGEX.ordinal()), 55);

        setWidth(cm.getColumn(Col.MODE.ordinal()), 90);
        setWidth(cm.getColumn(Col.TYPE.ordinal()), 100);
        setWidth(cm.getColumn(Col.TEXT.ordinal()), 160);
        setWidth(cm.getColumn(Col.POS.ordinal()), 70);
        setWidth(cm.getColumn(Col.LEN.ordinal()), 60);

        for (int i = Col.DEC1.ordinal(); i <= Col.ENC4.ordinal(); i++) {
            setWidth(cm.getColumn(i), 90);
        }

        table.setDefaultRenderer(Object.class, new RuleAwareRenderer());
        table.setDefaultRenderer(Integer.class, new RuleAwareRenderer());
        table.setDefaultRenderer(Boolean.class, new RuleAwareRenderer());
        table.setDefaultRenderer(MutationMode.class, new RuleAwareRenderer());
        table.setDefaultRenderer(RandomType.class, new RuleAwareRenderer());
        table.setDefaultRenderer(Position.class, new RuleAwareRenderer());
        table.setDefaultRenderer(CodecOp.class, new RuleAwareRenderer());
        table.setDefaultRenderer(ParamMutatorRule.ParamPatternType.class, new RuleAwareRenderer());
    }

    private static void setWidth(TableColumn c, int w) {
        c.setPreferredWidth(w);
        c.setMinWidth(w);
        c.setMaxWidth(w);
    }

    private static void setupGroupedHeader(GroupableTableHeader header) {
        TableColumnModel cm = header.getColumnModel();

        TableCellRenderer groupRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

                JTableHeader th = table.getTableHeader();
                JLabel l = (JLabel) super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);

                if (th != null) {
                    l.setForeground(th.getForeground());
                    l.setBackground(th.getBackground());
                    l.setFont(th.getFont());
                }

                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setText(value == null ? "" : value.toString());
                l.setBorder(UIManager.getBorder("TableHeader.cellBorder"));
                l.setOpaque(true);
                return l;
            }
        };

        ColumnGroup gParam = new ColumnGroup("PARAMETER");
        gParam.setHeaderRenderer(groupRenderer);
        gParam.add(cm.getColumn(Col.PARAM_PATTERN.ordinal()));
        gParam.add(cm.getColumn(Col.PARAM_TYPE.ordinal()));

        ColumnGroup gPath = new ColumnGroup("PATH");
        gPath.setHeaderRenderer(groupRenderer);
        gPath.add(cm.getColumn(Col.PATH_ENABLED.ordinal()));
        gPath.add(cm.getColumn(Col.PATH_PATTERN.ordinal()));
        gPath.add(cm.getColumn(Col.PATH_REGEX.ordinal()));

        ColumnGroup gOptions = new ColumnGroup("OPTIONS");
        gOptions.setHeaderRenderer(groupRenderer);
        gOptions.add(cm.getColumn(Col.MODE.ordinal()));
        gOptions.add(cm.getColumn(Col.TYPE.ordinal()));
        gOptions.add(cm.getColumn(Col.TEXT.ordinal()));
        gOptions.add(cm.getColumn(Col.POS.ordinal()));
        gOptions.add(cm.getColumn(Col.LEN.ordinal()));

        ColumnGroup gEnc = new ColumnGroup("ENCODING");
        gEnc.setHeaderRenderer(groupRenderer);
        gEnc.add(cm.getColumn(Col.DEC1.ordinal()));
        gEnc.add(cm.getColumn(Col.DEC2.ordinal()));
        gEnc.add(cm.getColumn(Col.DEC3.ordinal()));
        gEnc.add(cm.getColumn(Col.DEC4.ordinal()));
        gEnc.add(cm.getColumn(Col.ENC1.ordinal()));
        gEnc.add(cm.getColumn(Col.ENC2.ordinal()));
        gEnc.add(cm.getColumn(Col.ENC3.ordinal()));
        gEnc.add(cm.getColumn(Col.ENC4.ordinal()));

        header.addColumnGroup(gParam);
        header.addColumnGroup(gPath);
        header.addColumnGroup(gOptions);
        header.addColumnGroup(gEnc);

        header.revalidate();
        header.repaint();
    }

    // -------------------- Model & row state --------------------

    private static final class RuleRow {
        String paramPattern = "";
        ParamMutatorRule.ParamPatternType paramType = ParamMutatorRule.ParamPatternType.NORMAL;

        boolean pathEnabled = false;
        String pathPattern = "";
        boolean pathRegex = false;

        MutationMode mode = MutationMode.RANDOM;
        RandomType randType = RandomType.NUMERIC;
        String text = "change_me";
        Position position = Position.PREFIX;
        int length = 4;

        CodecOp dec1 = CodecOp.NO_OP;
        CodecOp dec2 = CodecOp.NO_OP;
        CodecOp dec3 = CodecOp.NO_OP;
        CodecOp dec4 = CodecOp.NO_OP;

        CodecOp enc1 = CodecOp.NO_OP;
        CodecOp enc2 = CodecOp.NO_OP;
        CodecOp enc3 = CodecOp.NO_OP;
        CodecOp enc4 = CodecOp.NO_OP;
    }

    private static final class RuleTableModel extends AbstractTableModel {
        private final int maxRows;
        private int visibleRows = 15;
        private final List<RuleRow> rows = new ArrayList<>();

        RuleTableModel(int maxRows) {
            this.maxRows = maxRows;
            for (int i = 0; i < maxRows; i++) rows.add(new RuleRow());
        }

        void setVisibleRowCount(int n) {
            visibleRows = Math.max(1, Math.min(maxRows, n));
            fireTableDataChanged();
        }

        int getVisibleRowCount() {
            return visibleRows;
        }

        @Override public int getRowCount() { return visibleRows; }
        @Override public int getColumnCount() { return Col.values().length; }
        @Override public String getColumnName(int column) { return Col.values()[column].header; }
        @Override public Class<?> getColumnClass(int columnIndex) { return Col.values()[columnIndex].cls; }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            RuleRow r = rows.get(rowIndex);
            Col c = Col.values()[columnIndex];

            if (c == Col.PARAM_PATTERN || c == Col.PARAM_TYPE || c == Col.MODE) return true;

            if (c == Col.PATH_ENABLED) return true;
            if (c == Col.PATH_PATTERN || c == Col.PATH_REGEX) return r.pathEnabled;

            if (c == Col.TYPE) return r.mode == MutationMode.RANDOM;
            if (c == Col.LEN) {
                return r.mode == MutationMode.RANDOM && r.randType != RandomType.UUID;
            }
            if (c == Col.TEXT) return r.mode == MutationMode.STRING;

            if (c == Col.POS) return r.paramType != ParamMutatorRule.ParamPatternType.USER_DEF;

            // decoding should be disabled for user_def
            if (c == Col.DEC1 || c == Col.DEC2 || c == Col.DEC3 || c == Col.DEC4) {
                return r.paramType != ParamMutatorRule.ParamPatternType.USER_DEF;
            }

            // encoding always editable
            if (c == Col.ENC1 || c == Col.ENC2 || c == Col.ENC3 || c == Col.ENC4) {
                return true;
            }

            return false;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RuleRow r = rows.get(rowIndex);
            Col c = Col.values()[columnIndex];
            return switch (c) {
                case PARAM_PATTERN -> r.paramPattern;
                case PARAM_TYPE -> r.paramType;

                case PATH_ENABLED -> r.pathEnabled;
                case PATH_PATTERN -> r.pathPattern;
                case PATH_REGEX -> r.pathRegex;

                case MODE -> r.mode;
                case TYPE -> r.randType;
                case TEXT -> r.text;
                case POS -> r.position;
                case LEN -> r.length;

                case DEC1 -> r.dec1;
                case DEC2 -> r.dec2;
                case DEC3 -> r.dec3;
                case DEC4 -> r.dec4;

                case ENC1 -> r.enc1;
                case ENC2 -> r.enc2;
                case ENC3 -> r.enc3;
                case ENC4 -> r.enc4;
            };
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            RuleRow r = rows.get(rowIndex);
            Col c = Col.values()[columnIndex];

            try {
                switch (c) {
                    case PARAM_PATTERN -> r.paramPattern = aValue == null ? "" : aValue.toString();
                    case PARAM_TYPE -> r.paramType = (ParamMutatorRule.ParamPatternType) aValue;

                    case PATH_ENABLED -> r.pathEnabled = aValue instanceof Boolean && (Boolean) aValue;
                    case PATH_PATTERN -> r.pathPattern = aValue == null ? "" : aValue.toString();
                    case PATH_REGEX -> r.pathRegex = aValue instanceof Boolean && (Boolean) aValue;

                    case MODE -> {
                        r.mode = (MutationMode) aValue;
                        if (r.mode == MutationMode.STRING && (r.text == null || r.text.isEmpty())) r.text = "X";
                    }
                    case TYPE -> r.randType = (RandomType) aValue;
                    case TEXT -> r.text = aValue == null ? "" : aValue.toString();
                    case POS -> r.position = (Position) aValue;
                    case LEN -> {
                        if (aValue instanceof Integer) {
                            r.length = (Integer) aValue;
                        } else {
                            String s = aValue == null ? "" : aValue.toString().trim();
                            r.length = s.isEmpty() ? 4 : Integer.parseInt(s);
                        }
                    }

                    case DEC1 -> r.dec1 = (CodecOp) aValue;
                    case DEC2 -> r.dec2 = (CodecOp) aValue;
                    case DEC3 -> r.dec3 = (CodecOp) aValue;
                    case DEC4 -> r.dec4 = (CodecOp) aValue;

                    case ENC1 -> r.enc1 = (CodecOp) aValue;
                    case ENC2 -> r.enc2 = (CodecOp) aValue;
                    case ENC3 -> r.enc3 = (CodecOp) aValue;
                    case ENC4 -> r.enc4 = (CodecOp) aValue;
                }
            } catch (Exception ex) {
                // ignore
            }

            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    // -------------------- Renderers/editors --------------------

    private static final class RuleAwareRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            RuleTableModel m = (RuleTableModel) table.getModel();
            RuleRow rr = m.rows.get(row);

            Col colEnum = Col.values()[table.convertColumnIndexToModel(column)];

            boolean enabled = true;
            if (colEnum == Col.PATH_PATTERN || colEnum == Col.PATH_REGEX) enabled = rr.pathEnabled;
            if (colEnum == Col.TYPE) enabled = rr.mode == MutationMode.RANDOM;
            if (colEnum == Col.LEN) {
                enabled = rr.mode == MutationMode.RANDOM && rr.randType != RandomType.UUID;
            }
            if (colEnum == Col.TEXT) enabled = rr.mode == MutationMode.STRING;
            if (colEnum == Col.POS) enabled = rr.paramType != ParamMutatorRule.ParamPatternType.USER_DEF;

            // gray out decode for user_def
            if (colEnum == Col.DEC1 || colEnum == Col.DEC2 || colEnum == Col.DEC3 || colEnum == Col.DEC4) {
                enabled = rr.paramType != ParamMutatorRule.ParamPatternType.USER_DEF;
            }

            c.setEnabled(enabled);
            return c;
        }
    }

    private static final class IntegerCellEditor extends DefaultCellEditor {
        private final int min;
        private final int max;

        IntegerCellEditor(int min, int max) {
            super(new JTextField());
            this.min = min;
            this.max = max;
        }

        @Override
        public Object getCellEditorValue() {
            String s = ((JTextField) getComponent()).getText();
            try {
                int v = Integer.parseInt(s.trim());
                if (v < min) v = min;
                if (v > max) v = max;
                return v;
            } catch (Exception e) {
                return min;
            }
        }
    }

    // -------------------- Grouped header (unchanged from your base) --------------------

    public static class ColumnGroup {
        protected TableCellRenderer renderer;
        protected Vector<Object> v = new Vector<>();
        protected String text;
        protected int margin = 0;

        public ColumnGroup(String text) {
            this.text = text;
            this.renderer = null;
        }

        public void add(Object obj) {
            if (obj == null) return;
            v.addElement(obj);
        }

        public Vector<Object> getColumnGroups(TableColumn col, Vector<Object> g) {
            g.addElement(this);
            if (v.contains(col)) return g;

            Enumeration<?> en = v.elements();
            while (en.hasMoreElements()) {
                Object obj = en.nextElement();
                if (obj instanceof ColumnGroup) {
                    Vector<Object> groups = ((ColumnGroup) obj).getColumnGroups(col, (Vector<Object>) g.clone());
                    if (groups != null) return groups;
                }
            }
            return null;
        }

        public TableCellRenderer getHeaderRenderer() {
            return renderer;
        }

        public void setHeaderRenderer(TableCellRenderer renderer) {
            this.renderer = renderer;
        }

        public Object getHeaderValue() {
            return text;
        }

        public Dimension getSize(JTable table) {
            Component comp = getHeaderRendererComponent(table, getHeaderValue(), false, false, -1, -1);
            int height = comp.getPreferredSize().height;
            int width = 0;
            Enumeration<?> en = v.elements();
            while (en.hasMoreElements()) {
                Object obj = en.nextElement();
                if (obj instanceof TableColumn) {
                    TableColumn aColumn = (TableColumn) obj;
                    width += aColumn.getWidth();
                    width += margin;
                } else {
                    width += ((ColumnGroup) obj).getSize(table).width;
                }
            }
            return new Dimension(width, height);
        }

        public void setColumnMargin(int margin) {
            this.margin = margin;
            Enumeration<?> en = v.elements();
            while (en.hasMoreElements()) {
                Object obj = en.nextElement();
                if (obj instanceof ColumnGroup) {
                    ((ColumnGroup) obj).setColumnMargin(margin);
                }
            }
        }

        public Component getHeaderRendererComponent(JTable table, Object value,
                                                    boolean isSelected, boolean hasFocus, int row, int column) {
            TableCellRenderer r = getHeaderRenderer();
            if (r == null) {
                JTableHeader header = table.getTableHeader();
                r = header.getDefaultRenderer();
            }
            return r.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        }
    }

    public static class GroupableTableHeader extends JTableHeader {
        private Vector<ColumnGroup> columnGroups = null;

        public GroupableTableHeader(TableColumnModel model) {
            super(model);
            setUI(new GroupableTableHeaderUI());
            setReorderingAllowed(false);
        }

        public void addColumnGroup(ColumnGroup g) {
            if (columnGroups == null) columnGroups = new Vector<>();
            columnGroups.addElement(g);
        }

        public Enumeration<?> getColumnGroups(TableColumn col) {
            if (columnGroups == null) return null;
            Enumeration<ColumnGroup> en = columnGroups.elements();
            while (en.hasMoreElements()) {
                ColumnGroup cGroup = en.nextElement();
                Vector<Object> v = cGroup.getColumnGroups(col, new Vector<>());
                if (v != null) return v.elements();
            }
            return null;
        }

        public void setColumnMargin() {
            int columnMargin = getColumnModel().getColumnMargin();
            if (columnGroups == null) return;
            Enumeration<ColumnGroup> en = columnGroups.elements();
            while (en.hasMoreElements()) {
                ColumnGroup cGroup = en.nextElement();
                cGroup.setColumnMargin(columnMargin);
            }
        }
    }

    public static class GroupableTableHeaderUI extends BasicTableHeaderUI {

        @Override
        public void paint(Graphics g, JComponent c) {
            Rectangle clipBounds = g.getClipBounds();
            if (header.getColumnModel() == null) return;

            ((GroupableTableHeader) header).setColumnMargin();

            int column = 0;
            Dimension size = header.getSize();
            Rectangle cellRect = new Rectangle(0, 0, size.width, size.height);

            Map<ColumnGroup, Rectangle> h = new HashMap<>();
            int columnMargin = header.getColumnModel().getColumnMargin();

            Enumeration<TableColumn> enumeration = header.getColumnModel().getColumns();
            while (enumeration.hasMoreElements()) {
                cellRect.height = size.height;
                cellRect.y = 0;

                TableColumn aColumn = enumeration.nextElement();
                Enumeration<?> cGroups = ((GroupableTableHeader) header).getColumnGroups(aColumn);

                if (cGroups != null) {
                    int groupHeight = 0;

                    while (cGroups.hasMoreElements()) {
                        ColumnGroup cGroup = (ColumnGroup) cGroups.nextElement();
                        Rectangle groupRect = h.get(cGroup);

                        if (groupRect == null) {
                            groupRect = new Rectangle(cellRect);
                            Dimension d = cGroup.getSize(header.getTable());
                            groupRect.width = d.width;
                            groupRect.height = d.height;
                            h.put(cGroup, groupRect);
                        }

                        paintCell(g, groupRect, cGroup);

                        groupHeight += groupRect.height;
                        cellRect.y = groupHeight;
                        cellRect.height = size.height - cellRect.y;
                    }
                }

                cellRect.width = aColumn.getWidth() + columnMargin;

                if (cellRect.intersects(clipBounds)) {
                    paintCell(g, cellRect, column);
                }

                cellRect.x += cellRect.width;
                column++;
            }
        }

        private void paintCell(Graphics g, Rectangle cellRect, int columnIndex) {
            TableColumn aColumn = header.getColumnModel().getColumn(columnIndex);
            TableCellRenderer renderer = aColumn.getHeaderRenderer();
            if (renderer == null) renderer = header.getDefaultRenderer();

            Component component = renderer.getTableCellRendererComponent(
                    header.getTable(), aColumn.getHeaderValue(), false, false, -1, columnIndex);

            rendererPane.add(component);
            rendererPane.paintComponent(g, component, header,
                    cellRect.x, cellRect.y, cellRect.width, cellRect.height, true);
        }

        private void paintCell(Graphics g, Rectangle cellRect, ColumnGroup cGroup) {
            TableCellRenderer renderer = cGroup.getHeaderRenderer();
            if (renderer == null) renderer = header.getDefaultRenderer();

            Component component = renderer.getTableCellRendererComponent(
                    header.getTable(), cGroup.getHeaderValue(), false, false, -1, -1);

            rendererPane.add(component);
            rendererPane.paintComponent(g, component, header,
                    cellRect.x, cellRect.y, cellRect.width, cellRect.height, true);
        }

        private int getHeaderHeight() {
            int height = 0;
            TableColumnModel columnModel = header.getColumnModel();

            for (int column = 0; column < columnModel.getColumnCount(); column++) {
                TableColumn aColumn = columnModel.getColumn(column);
                TableCellRenderer renderer = aColumn.getHeaderRenderer();
                if (renderer == null) renderer = header.getDefaultRenderer();

                Component comp = renderer.getTableCellRendererComponent(
                        header.getTable(), aColumn.getHeaderValue(), false, false, -1, column);

                int cHeight = comp.getPreferredSize().height;

                Enumeration<?> en = ((GroupableTableHeader) header).getColumnGroups(aColumn);
                if (en != null) {
                    while (en.hasMoreElements()) {
                        ColumnGroup cGroup = (ColumnGroup) en.nextElement();
                        cHeight += cGroup.getSize(header.getTable()).height;
                    }
                }

                height = Math.max(height, cHeight);
            }

            return height;
        }

        private Dimension createHeaderSize(long width) {
            TableColumnModel columnModel = header.getColumnModel();
            width += (long) columnModel.getColumnMargin() * columnModel.getColumnCount();
            if (width > Integer.MAX_VALUE) width = Integer.MAX_VALUE;
            return new Dimension((int) width, getHeaderHeight());
        }

        @Override
        public Dimension getPreferredSize(JComponent c) {
            long width = 0;
            Enumeration<TableColumn> enumeration = header.getColumnModel().getColumns();
            while (enumeration.hasMoreElements()) {
                TableColumn aColumn = enumeration.nextElement();
                width += aColumn.getPreferredWidth();
            }
            return createHeaderSize(width);
        }
    }
}
