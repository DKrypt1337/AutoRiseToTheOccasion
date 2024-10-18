import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import javax.swing.DefaultListSelectionModel;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.ITab;
import burp.ITextEditor;

public class AutoRiseToTheOccasion implements IBurpExtender, ITab, ListSelectionListener {
    private JCheckBox[] roleCheckBoxes;
    private JCheckBox[] enableCookiesCheckBoxes;
    private JCheckBox[] enableAuthorizationCheckBoxes;
    private ITextEditor[] requestViewers;
    private ITextEditor[] modifiedRequestViewers;
    private ITextEditor[] responseViewers;
    private ITextEditor[] modifiedResponseViewers;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private DefaultTableModel[] tableModels;
    private JTable[] tables;
    private JScrollPane[] requestScrollPanes;
    private JPanel[] requestPanels;
    private Map<String, IHttpRequestResponse> requestMap;
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private int requestCounter;
    private final Map<Integer, Map<Integer, IHttpRequestResponse>> userRequestResponseMap = new HashMap<>();

    public void logInfo(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        stdout.println("[" + timestamp + "] INFO: " + message);
    }

    public void logError(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        stdout.println("[" + timestamp + "] ERROR: " + message);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.mainPanel = new JPanel(new BorderLayout());
        this.tabbedPane = new JTabbedPane();
        this.requestMap = new HashMap<>();
        this.requestCounter = 0;

        // Obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // Initialize arrays
        int userCount = 10;
        roleCheckBoxes = new JCheckBox[userCount];
        enableCookiesCheckBoxes = new JCheckBox[userCount];
        enableAuthorizationCheckBoxes = new JCheckBox[userCount];
        requestViewers = new ITextEditor[userCount];
        modifiedRequestViewers = new ITextEditor[userCount];
        responseViewers = new ITextEditor[userCount];
        modifiedResponseViewers = new ITextEditor[userCount];
        tableModels = new DefaultTableModel[userCount];
        tables = new JTable[userCount];
        requestPanels = new JPanel[userCount];

        // Initialize components for each user
        for (int i = 0; i < userCount; i++) {
            roleCheckBoxes[i] = new JCheckBox("Enable Role");
            enableCookiesCheckBoxes[i] = new JCheckBox("Enable Cookies");
            enableAuthorizationCheckBoxes[i] = new JCheckBox("Enable Authorization");

            requestViewers[i] = callbacks.createTextEditor();
            modifiedRequestViewers[i] = callbacks.createTextEditor();
            responseViewers[i] = callbacks.createTextEditor();
            modifiedResponseViewers[i] = callbacks.createTextEditor();

            tableModels[i] = new DefaultTableModel(new Object[]{"ID", "Method", "URL", "Status", "Bypassed"}, 0);
            tables[i] = new JTable(tableModels[i]);
            tables[i].getSelectionModel().addListSelectionListener(this);
            adjustColumnWidths(tables[i]);

            // Set fixed sizes for the table
            tables[i].setPreferredScrollableViewportSize(new Dimension(500, 200));
            tables[i].setFillsViewportHeight(true);

            JPanel userPanel = new JPanel(new BorderLayout());
            JPanel checkBoxPanel = new JPanel(new GridLayout(1, 4));
            checkBoxPanel.add(roleCheckBoxes[i]);
            checkBoxPanel.add(enableCookiesCheckBoxes[i]);
            checkBoxPanel.add(enableAuthorizationCheckBoxes[i]);

            userPanel.add(checkBoxPanel, BorderLayout.NORTH);
            userPanel.add(new JScrollPane(tables[i]), BorderLayout.CENTER);

            JTabbedPane requestResponseTabbedPane = new JTabbedPane();
            JPanel originalPanel = new JPanel(new GridLayout(2, 1));
            originalPanel.add(new JScrollPane(requestViewers[i].getComponent()));
            originalPanel.add(new JScrollPane(responseViewers[i].getComponent()));
            requestResponseTabbedPane.addTab("Original", originalPanel);

            JPanel modifiedPanel = new JPanel(new GridLayout(2, 1));
            modifiedPanel.add(new JScrollPane(modifiedRequestViewers[i].getComponent()));
            modifiedPanel.add(new JScrollPane(modifiedResponseViewers[i].getComponent()));
            requestResponseTabbedPane.addTab("Modified", modifiedPanel);

            // Set fixed sizes for the request/response viewers
            requestViewers[i].getComponent().setPreferredSize(new Dimension(500, 200));
            responseViewers[i].getComponent().setPreferredSize(new Dimension(500, 200));
            modifiedRequestViewers[i].getComponent().setPreferredSize(new Dimension(500, 200));
            modifiedResponseViewers[i].getComponent().setPreferredSize(new Dimension(500, 200));

            userPanel.add(requestResponseTabbedPane, BorderLayout.SOUTH);

            tabbedPane.addTab("User " + (i + 1), userPanel);

            // Add action listener to roleCheckBox
            final int userIndex = i;
            roleCheckBoxes[userIndex].addActionListener(e -> {
                if (roleCheckBoxes[userIndex].isSelected()) {
                    // Enable capturing requests for this user
                    callbacks.registerHttpListener(new AutoRiseHttpListener(this, userIndex));
                } else {
                    // Disable capturing requests for this user
                    callbacks.removeHttpListener(new AutoRiseHttpListener(this, userIndex));
                }
            });
        }

        // Add unauthenticated user tab
        JPanel unauthenticatedPanel = new JPanel(new BorderLayout());
        unauthenticatedPanel.add(new JLabel("Unauthenticated User"), BorderLayout.NORTH);
        tabbedPane.addTab("Unauthenticated", unauthenticatedPanel);

        // Add config tab
        JPanel configPanel = new JPanel(new BorderLayout());
        configPanel.add(new JLabel("Configuration"), BorderLayout.NORTH);
        tabbedPane.addTab("Config", configPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        callbacks.customizeUiComponent(mainPanel);
        callbacks.addSuiteTab(this);

        // Call initializeTableModel() in your initialization code
                initializeTableModel();
            }
        
        // Adjust column widths and add "Bypassed" column
        private void adjustColumnWidths(JTable table) {
            TableColumnModel columnModel = table.getColumnModel();
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            columnModel.getColumn(0).setPreferredWidth(100); // ID
            columnModel.getColumn(1).setPreferredWidth(100); // Method
            columnModel.getColumn(2).setPreferredWidth(1200); // URLs
            columnModel.getColumn(3).setPreferredWidth(100); // Status
            columnModel.getColumn(4).setPreferredWidth(100); // Bypassed
        }
        
        // Update the table model to include the "Bypassed" column
        private void initializeTableModel() {
            for (int i = 0; i < tables.length; i++) {
                tableModels[i] = new DefaultTableModel(new Object[]{"ID", "Method", "URL", "Status", "Bypassed"}, 0);
                tables[i].setModel(tableModels[i]);
                adjustColumnWidths(tables[i]);
            }
        }
        
        // Update the processHttpMessage method to handle the "Bypassed" column using SwingWorker
        public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo, int userIndex) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            String method = requestInfo.getMethod();
            String url = requestInfo.getUrl().toString();

            // Use a combination of method, URL, and possibly headers to track unique requests
            String uniqueRequestKey = method + ":" + url;

            // Check if the "Enable Role" checkbox is checked
            if (roleCheckBoxes[userIndex].isSelected()) {
                if (messageIsRequest) {
                    int id = requestCounter++;
                    logInfo("Processing request: ID=" + id + ", Method=" + method + ", URL=" + url);

                    // Check if this request is a duplicate
                    boolean isDuplicate = requestMap.containsKey(uniqueRequestKey);
                    if (!isDuplicate) {
                        tableModels[userIndex].addRow(new Object[]{id, method, url, "", "Not checked"});
                        requestMap.put(uniqueRequestKey, messageInfo);
                        userRequestResponseMap.computeIfAbsent(userIndex, k -> new HashMap<>()).put(id, messageInfo);

                        // Store the ID in the IHttpRequestResponse object
                        messageInfo.setComment(String.valueOf(id));
                    } else {
                        logInfo("Duplicate request detected: " + url);
                    }
                } else {
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            byte[] response = messageInfo.getResponse();
                            if (response != null) {
                                short statusCode = helpers.analyzeResponse(response).getStatusCode();
                                logInfo("Processing response: Status Code=" + statusCode);

                                // Retrieve the ID from the IHttpRequestResponse object
                                int id = Integer.parseInt(messageInfo.getComment());

                                // Update the IHttpRequestResponse object with the response
                                messageInfo.setResponse(response);

                                // Find the corresponding request and update the status code and bypassed column
                                for (int i = 0; i < tableModels[userIndex].getRowCount(); i++) {
                                    Integer requestId = (Integer) tableModels[userIndex].getValueAt(i, 0);
                                    if (requestId != null && requestId.equals(id)) {
                                        tableModels[userIndex].setValueAt(statusCode, i, 3);

                                        // Check if the request is bypassed
                                        if (enableCookiesCheckBoxes[userIndex].isSelected() || enableAuthorizationCheckBoxes[userIndex].isSelected()) {
                                            boolean isBypassed = statusCode >= 200;
                                            String bypassedValue = isBypassed ? "✔" : "✘";
                                            tableModels[userIndex].setValueAt(bypassedValue, i, 4);

                                            // Set the color for the bypassed column
                                            TableCellRenderer renderer = new DefaultTableCellRenderer() {
                                                @Override
                                                public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                                                    Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                                                    if (column == 4) {
                                                        if ("✔".equals(value)) {
                                                            c.setBackground(new Color(0, 128, 0)); // Darker green
                                                        } else if (statusCode >= 300 && statusCode < 400) {
                                                            c.setBackground(Color.YELLOW); // Yellow
                                                        } else if (statusCode >= 400) {
                                                            c.setBackground(new Color(139, 0, 0)); // Darker red
                                                        } else {
                                                            c.setBackground(Color.WHITE);
                                                        }
                                                    } else {
                                                        c.setBackground(Color.WHITE);
                                                    }
                                                    return c;
                                                }
                                            };
                                            tables[userIndex].getColumnModel().getColumn(4).setCellRenderer(renderer);
                                        } else {
                                            tableModels[userIndex].setValueAt("Not checked", i, 4);
                                        }

                                        break;
                                    }
                                }

                                // Update the userRequestResponseMap with the modified messageInfo
                                userRequestResponseMap.get(userIndex).put(id, messageInfo);
                            } else {
                                logInfo("Response is null for ID=" + messageInfo.getComment());
                            }
                            return null;
                        }

                        @Override
                        protected void done() {
                            // Any post-processing can be done here if needed
                        }
                    }.execute();
                }
            }
        }

        @Override
        public void valueChanged(ListSelectionEvent e) {
            logInfo("valueChanged called");
            if (!e.getValueIsAdjusting()) {
                logInfo("Event is not adjusting");
                try {
                    Object source = e.getSource();
                    JTable sourceTable = null;
        
                    if (source instanceof JTable) {
                        sourceTable = (JTable) source;
                    } else if (source instanceof DefaultListSelectionModel) {
                        for (JTable table : tables) {
                            if (table.getSelectionModel() == source) {
                                sourceTable = table;
                                break;
                            }
                        }
                    }
        
                    if (sourceTable != null) {
                        logInfo("Source table: " + sourceTable);
                        int selectedRow = sourceTable.getSelectedRow();
                        logInfo("Selected row: " + selectedRow);
                        if (selectedRow >= 0) {
                            boolean tableMatched = false;
                            for (int i = 0; i < tables.length; i++) {
                                if (tables[i] == sourceTable) {
                                    tableMatched = true;
                                    logInfo("Source table matched for user index: " + i);
                                    Object idObject = tableModels[i].getValueAt(selectedRow, 0);
                                    if (idObject != null) {
                                        int id = (int) idObject;
                                        logInfo("Selected ID: " + id);
                                        IHttpRequestResponse messageInfo = userRequestResponseMap.get(i).get(id);
                                        if (messageInfo != null) {
                                            logInfo("Displaying request and response for ID=" + id);
                                            byte[] request = messageInfo.getRequest();
                                            byte[] response = messageInfo.getResponse();
                                            if (request != null) {
                                                logInfo("Request length: " + request.length);
                                                requestViewers[i].setText(request);
                                            } else {
                                                logError("Request is null for ID=" + id);
                                            }
                                            if (response != null) {
                                                logInfo("Response length: " + response.length);
                                                responseViewers[i].setText(response);
                                            } else {
                                                logError("Response is null for ID=" + id);
                                            }
                                        } else {
                                            logError("No message info found for ID=" + id);
                                        }
                                    } else {
                                        logError("ID object is null at selected row: " + selectedRow);
                                    }
                                }
                            }
                            if (!tableMatched) {
                                logError("No matching table found for the source table");
                            }
                        } else {
                            logError("No row is selected");
                        }
                    } else {
                        if (source != null) {
                            logError("Event source is not a JTable or associated with any JTable: " + source.getClass().getName());
                        } else {
                            logError("Event source is null");
                        }
                    }
                } catch (Exception ex) {
                    logError("Exception occurred in valueChanged: " + ex.getMessage());
                    logError("Exception stack trace: " + ex.toString());
                }
            }
        }

    @Override
    public String getTabCaption() {
        return "AutoRiseToTheOccasion";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // Inner class for HTTP Listener
    public class AutoRiseHttpListener implements IHttpListener {
        private final AutoRiseToTheOccasion extender;
        private final int userIndex;

        public AutoRiseHttpListener(AutoRiseToTheOccasion extender, int userIndex) {
            this.extender = extender;
            this.userIndex = userIndex;
        }

        @Override
        public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
            extender.processHttpMessage(toolFlag, messageIsRequest, messageInfo, userIndex);
        }
    }
}