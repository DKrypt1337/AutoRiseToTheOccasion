import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.DefaultListSelectionModel;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
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
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private JTable[] tables;
    private DefaultTableModel[] tableModels;
    private ITextEditor[] requestViewers;
    private ITextEditor[] modifiedRequestViewers;
    private ITextEditor[] responseViewers;
    private ITextEditor[] modifiedResponseViewers;
    private JCheckBox[] roleCheckBoxes;
    private JCheckBox[] enableCookiesCheckBoxes;
    private JCheckBox[] enableAuthorizationCheckBoxes;
    private JTextField[] cookieInputBoxes;
    private JTextField[] authInputBoxes;
    private Map<String, IHttpRequestResponse> requestMap = new HashMap<>();
    private Map<Integer, Map<Integer, IHttpRequestResponse>> userRequestResponseMap = new HashMap<>();
    private int requestCounter = 0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("AutoRiseToTheOccasion");

        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());
            tabbedPane = new JTabbedPane();
            int userCount = 3; // Example user count
            tables = new JTable[userCount];
            tableModels = new DefaultTableModel[userCount];
            requestViewers = new ITextEditor[userCount];
            modifiedRequestViewers = new ITextEditor[userCount];
            responseViewers = new ITextEditor[userCount];
            modifiedResponseViewers = new ITextEditor[userCount];
            roleCheckBoxes = new JCheckBox[userCount];
            enableCookiesCheckBoxes = new JCheckBox[userCount];
            enableAuthorizationCheckBoxes = new JCheckBox[userCount];
            cookieInputBoxes = new JTextField[userCount];
            authInputBoxes = new JTextField[userCount];

            for (int i = 0; i < userCount; i++) {
                JPanel userPanel = new JPanel(new BorderLayout());
                tableModels[i] = new DefaultTableModel(new Object[]{"ID", "Method", "URL", "Status", "Bypassed"}, 0);
                tables[i] = new JTable(tableModels[i]);
                adjustColumnWidths(tables[i]);
                tables[i].getSelectionModel().addListSelectionListener(this);

                requestViewers[i] = callbacks.createTextEditor();
                modifiedRequestViewers[i] = callbacks.createTextEditor();
                responseViewers[i] = callbacks.createTextEditor();
                modifiedResponseViewers[i] = callbacks.createTextEditor();

                roleCheckBoxes[i] = new JCheckBox("Enable Role " + (i + 1));
                enableCookiesCheckBoxes[i] = new JCheckBox("Enable Cookies");
                enableAuthorizationCheckBoxes[i] = new JCheckBox("Enable Authorization");
                cookieInputBoxes[i] = new JTextField(20);
                authInputBoxes[i] = new JTextField(20);

                JPanel checkBoxPanel = new JPanel(new GridLayout(1, 5));
                checkBoxPanel.add(roleCheckBoxes[i]);
                checkBoxPanel.add(enableCookiesCheckBoxes[i]);
                checkBoxPanel.add(cookieInputBoxes[i]);
                checkBoxPanel.add(enableAuthorizationCheckBoxes[i]);
                checkBoxPanel.add(authInputBoxes[i]);

                JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(tables[i]), new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(requestViewers[i].getComponent()), new JScrollPane(responseViewers[i].getComponent())));
                userPanel.add(checkBoxPanel, BorderLayout.NORTH);
                userPanel.add(splitPane, BorderLayout.CENTER);

                JTabbedPane requestResponseTabbedPane = new JTabbedPane();
                JPanel originalPanel = new JPanel(new GridLayout(2, 1));
                originalPanel.add(new JScrollPane(requestViewers[i].getComponent()));
                originalPanel.add(new JScrollPane(responseViewers[i].getComponent()));
                requestResponseTabbedPane.addTab("Original", originalPanel);

                JPanel modifiedPanel = new JPanel(new GridLayout(2, 1));
                modifiedPanel.add(new JScrollPane(modifiedRequestViewers[i].getComponent()));
                modifiedPanel.add(new JScrollPane(modifiedResponseViewers[i].getComponent()));
                requestResponseTabbedPane.addTab("Modified", modifiedPanel);

                userPanel.add(requestResponseTabbedPane, BorderLayout.SOUTH);

                tabbedPane.addTab("User " + (i + 1), userPanel);

                callbacks.registerHttpListener(new AutoRiseHttpListener(this, i));
            }

            mainPanel.add(tabbedPane, BorderLayout.CENTER);
            callbacks.customizeUiComponent(mainPanel);
            callbacks.addSuiteTab(this);
        });
    }

    private void adjustColumnWidths(JTable table) {
        TableColumnModel columnModel = table.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(50); // ID
        columnModel.getColumn(1).setPreferredWidth(50); // Method
        columnModel.getColumn(2).setPreferredWidth(300); // URL
        columnModel.getColumn(3).setPreferredWidth(50); // Status
        columnModel.getColumn(4).setPreferredWidth(50); // Bypassed
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
    }

    private void adjustRequestResponseBoxHeight() {
        for (int i = 0; i < requestViewers.length; i++) {
            requestViewers[i].getComponent().setPreferredSize(new Dimension(500, 200)); // Adjust height as needed
            responseViewers[i].getComponent().setPreferredSize(new Dimension(500, 200)); // Adjust height as needed
            modifiedRequestViewers[i].getComponent().setPreferredSize(new Dimension(500, 200)); // Adjust height as needed
            modifiedResponseViewers[i].getComponent().setPreferredSize(new Dimension(500, 200)); // Adjust height as needed
        }
    }

    private byte[] modifyRequest(byte[] request, int userIndex) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(request).substring(requestInfo.getBodyOffset());

        // Modify cookies if enabled
        if (enableCookiesCheckBoxes[userIndex].isSelected()) {
            String cookieHeader = headers.stream().filter(h -> h.startsWith("Cookie:")).findFirst().orElse(null);
            if (cookieHeader != null) {
                String[] cookies = cookieHeader.substring(8).split("; ");
                Map<String, String> cookieMap = Arrays.stream(cookies).map(c -> c.split("=")).collect(Collectors.toMap(a -> a[0], a -> a[1]));
                String[] userCookies = cookieInputBoxes[userIndex].getText().split("; ");
                for (String userCookie : userCookies) {
                    String[] parts = userCookie.split("=");
                    if (parts.length == 2) {
                        cookieMap.put(parts[0], parts[1]);
                    }
                }
                String newCookieHeader = "Cookie: " + cookieMap.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.joining("; "));
                headers = headers.stream().filter(h -> !h.startsWith("Cookie:")).collect(Collectors.toList());
                headers.add(newCookieHeader);
            }
        }

        // Modify authorization if enabled
        if (enableAuthorizationCheckBoxes[userIndex].isSelected()) {
            String authHeader = headers.stream().filter(h -> h.startsWith("Authorization:")).findFirst().orElse(null);
            if (authHeader != null) {
                headers = headers.stream().filter(h -> !h.startsWith("Authorization:")).collect(Collectors.toList());
            }
            headers.add("Authorization: " + authInputBoxes[userIndex].getText());
        }

        return helpers.buildHttpMessage(headers, body.getBytes());
    }

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
                    tableModels[userIndex].addRow(new Object[]{id, method, url, "", "Original Request"});
                    requestMap.put(uniqueRequestKey, messageInfo);
                    userRequestResponseMap.computeIfAbsent(userIndex, k -> new HashMap<>()).put(id, messageInfo);

                    // Store the ID in the IHttpRequestResponse object
                    messageInfo.setComment(String.valueOf(id));
                } else {
                    logInfo("Duplicate request detected: " + url);
                }

                // Send duplicate request with modified values if checkboxes are enabled
                if (enableCookiesCheckBoxes[userIndex].isSelected() || enableAuthorizationCheckBoxes[userIndex].isSelected()) {
                    byte[] modifiedRequest = modifyRequest(messageInfo.getRequest(), userIndex);
                    IHttpRequestResponse modifiedMessageInfo = callbacks.makeHttpRequest(messageInfo.getHttpService(), modifiedRequest);
                    int modifiedId = requestCounter++;
                    tableModels[userIndex].addRow(new Object[]{modifiedId, method, url, "", "Modified Request"});
                    userRequestResponseMap.computeIfAbsent(userIndex, k -> new HashMap<>()).put(modifiedId, modifiedMessageInfo);

                    // Process the modified response
                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() throws Exception {
                            byte[] response = modifiedMessageInfo.getResponse();
                            if (response != null) {
                                short statusCode = helpers.analyzeResponse(response).getStatusCode();
                                logInfo("Processing modified response: Status Code=" + statusCode);

                                // Update the IHttpRequestResponse object with the response
                                modifiedMessageInfo.setResponse(response);

                                // Find the corresponding request and update the status code and bypassed column
                                for (int i = 0; i < tableModels[userIndex].getRowCount(); i++) {
                                    Integer requestId = (Integer) tableModels[userIndex].getValueAt(i, 0);
                                    if (requestId != null && requestId.equals(modifiedId)) {
                                        tableModels[userIndex].setValueAt(statusCode, i, 3);

                                        // Check if the request is bypassed
                                        if (enableCookiesCheckBoxes[userIndex].isSelected() || enableAuthorizationCheckBoxes[userIndex].isSelected()) {
                                            boolean isBypassed = statusCode >= 200 && statusCode < 300;
                                            String bypassedValue = isBypassed ? "✔" : "✘";
                                            tableModels[userIndex].setValueAt(bypassedValue, i, 4);
                                        } else {
                                            tableModels[userIndex].setValueAt("Not checked", i, 4);
                                        }

                                        break;
                                    }
                                }

                                // Update the userRequestResponseMap with the modified messageInfo
                                userRequestResponseMap.get(userIndex).put(modifiedId, modifiedMessageInfo);
                            } else {
                                logInfo("Response is null for ID=" + modifiedMessageInfo.getComment());
                            }
                            return null;
                        }

                        @Override
                        protected void done() {
                            // Any post-processing can be done here if needed
                            // Ensure the table is updated on the EDT
                            SwingUtilities.invokeLater(() -> tables[userIndex].repaint());
                        }
                    }.execute();
                }
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
                    logError("Event source is not a JTable or associated with any JTable: " + source.getClass().getName());
                }
            } catch (Exception ex) {
                logError("Exception occurred in valueChanged: " + ex.getMessage());
                ex.printStackTrace();
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

    private void logInfo(String message) {
        callbacks.printOutput(message);
    }

    private void logError(String message) {
        callbacks.printError(message);
    }
}