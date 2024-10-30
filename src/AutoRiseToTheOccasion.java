import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
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
    private int requestCounter = 0;
    private final Map<String, IHttpRequestResponse> requestMap = new HashMap<>();
    private final Map<Integer, Map<Integer, IHttpRequestResponse>> userRequestResponseMap = new HashMap<>();
    private final Set<String> processedRequestKeys = new HashSet<>();
    private final Object lock = new Object();

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

    private String generateRequestKey(IRequestInfo requestInfo) {
        String method = requestInfo.getMethod();
        String url = requestInfo.getUrl().toString();
        // Include additional headers or parameters if necessary
        return method + ":" + url;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("AutoRiseToTheOccasion");

        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());
            tabbedPane = new JTabbedPane();
            int userCount = 10; // User count
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

                JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(requestViewers[i].getComponent()), new JScrollPane(responseViewers[i].getComponent()));
                requestResponseSplitPane.setResizeWeight(0.5);
                requestResponseSplitPane.setDividerLocation(0.5);

                JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(tables[i]), requestResponseSplitPane);
                mainSplitPane.setResizeWeight(0.33);
                mainSplitPane.setDividerLocation(0.33);

                userPanel.add(checkBoxPanel, BorderLayout.NORTH);
                userPanel.add(mainSplitPane, BorderLayout.CENTER);

                tabbedPane.addTab("User " + (i + 1), userPanel);

                callbacks.registerHttpListener(new AutoRiseHttpListener(this, i));
            }

            adjustRequestResponseBoxHeight();
            mainPanel.add(tabbedPane, BorderLayout.CENTER);
            callbacks.customizeUiComponent(mainPanel);
            callbacks.addSuiteTab(this);
        });
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo, int userIndex) {
        if (!messageIsRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            String requestKey = generateRequestKey(requestInfo);
    
            synchronized (lock) {
                if (!processedRequestKeys.contains(requestKey)) {
                    processedRequestKeys.add(requestKey);
                    int id = requestCounter++;
                    logInfo("Processing response for request: " + requestKey + " with ID=" + id);
    
                    byte[] response = messageInfo.getResponse();
                    if (response != null) {
                        short statusCode = helpers.analyzeResponse(response).getStatusCode();
                        logInfo("Processing response with status code: " + statusCode);
    
                        // Store the request-response
                        requestMap.put(requestKey, messageInfo);
                        userRequestResponseMap
                            .computeIfAbsent(userIndex, k -> new HashMap<>())
                            .put(id, messageInfo);
    
                        // Add to the table
                        tableModels[userIndex].addRow(new Object[]{
                            id,
                            requestInfo.getMethod(),
                            requestInfo.getUrl().toString(),
                            statusCode,
                            ""
                        });
                        logInfo("Response added to table with ID=" + id);
                    } else {
                        logError("Response is null for request key: " + requestKey);
                    }
                }
            }
        }
    }

    @Override
public void valueChanged(ListSelectionEvent e) {
    if (!e.getValueIsAdjusting()) {
        try {
            for (int i = 0; i < tables.length; i++) {
                JTable table = tables[i];
                if (e.getSource() == table.getSelectionModel()) {
                    int selectedRow = table.getSelectedRow();
                    logInfo("Row selected in table for user index " + i + ": " + selectedRow);
                    if (selectedRow >= 0) {
                        Object idObject = tableModels[i].getValueAt(selectedRow, 0);
                        if (idObject != null) {
                            int id = (int) idObject;
                            logInfo("Fetching request-response for ID=" + id);
                            IHttpRequestResponse messageInfo = userRequestResponseMap.get(i).get(id);
                            if (messageInfo != null) {
                                byte[] request = messageInfo.getRequest();
                                byte[] response = messageInfo.getResponse();

                                final int viewerIndex = i;

                                SwingUtilities.invokeLater(() -> {
                                    if (request != null) {
                                        requestViewers[viewerIndex].setText(request);
                                        logInfo("Request displayed for ID=" + id + " in viewer index " + viewerIndex);
                                    } else {
                                        logError("Request is null for ID=" + id);
                                    }
                                    if (response != null) {
                                        responseViewers[viewerIndex].setText(response);
                                        logInfo("Response displayed for ID=" + id + " in viewer index " + viewerIndex);
                                    } else {
                                        logError("Response is null for ID=" + id);
                                    }
                                });
                            } else {
                                logError("No message info found for ID=" + id);
                            }
                        } else {
                            logError("ID object is null at selected row: " + selectedRow);
                        }
                    } else {
                        logError("No row is selected");
                    }
                    break; // Exit the loop after handling the event
                }
            }
        } catch (Exception ex) {
            logError("Exception in valueChanged: " + ex.getMessage());
            logError("Stack trace: " + Arrays.toString(ex.getStackTrace()));
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