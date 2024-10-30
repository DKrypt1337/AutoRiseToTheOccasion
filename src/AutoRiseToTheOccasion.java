import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
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
    private JCheckBox csrfTestCheckBox;
    private int requestCounter = 0;
    private final Map<String, IHttpRequestResponse> requestMap = new HashMap<>();
    Map<Integer, RequestResponsePair> requestResponseMap = new HashMap<>();
    private final Set<String> processedRequestKeys = new HashSet<>();
    private final Object lock = new Object();

    // Add these class fields to track modifications
    private class ModificationDetails {
        List<int[]> cookieHighlights = new ArrayList<>();
        List<int[]> authHighlights = new ArrayList<>();
    }
    private Map<Integer, ModificationDetails> highlightMap = new HashMap<>();

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

    class RequestResponsePair {
        int id;
        byte[] originalRequest;
        byte[] modifiedRequest;
        byte[] originalResponse;
        byte[] modifiedResponse;
        // Additional fields if necessary
    }

    // Update the modifyRequest method to track modification positions
    private byte[] modifyRequest(byte[] request, int userIndex, String requestId) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(request).substring(requestInfo.getBodyOffset());

        ModificationDetails modDetails = new ModificationDetails();
        highlightMap.put(Integer.valueOf(requestId), modDetails);

        boolean modified = false;
        
        // Check if Cookie header exists and should be modified
        if (enableCookiesCheckBoxes[userIndex].isSelected() && !cookieInputBoxes[userIndex].getText().trim().isEmpty()) {
            int cookieHeaderIndex = -1;
            String cookieHeader = null;
            
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).startsWith("Cookie:")) {
                    cookieHeader = headers.get(i);
                    cookieHeaderIndex = i;
                    break;
                }
            }

            // Only modify if Cookie header exists
            if (cookieHeader != null) {
                // Calculate the start position of the Cookie header in the full request
                int headerStart = 0;
                for (int i = 0; i < cookieHeaderIndex; i++) {
                    headerStart += headers.get(i).length() + 2; // +2 for \r\n
                }
                
                modDetails.cookieHighlights.add(new int[]{headerStart, headerStart + cookieHeader.length()});

                // Parse existing cookies into a LinkedHashMap to maintain order
                String[] existingCookies = cookieHeader.substring(8).split("; ");
                Map<String, String> cookieMap = Arrays.stream(existingCookies)
                    .map(c -> c.split("=", 2))
                    .filter(parts -> parts.length == 2)
                    .collect(Collectors.toMap(
                        parts -> parts[0],
                        parts -> parts[1],
                        (v1, v2) -> v2,
                        LinkedHashMap::new
                    ));

                // Only update specified cookies from input
                String userCookiesInput = cookieInputBoxes[userIndex].getText().trim();
                if (!userCookiesInput.isEmpty()) {
                    String[] userCookies = userCookiesInput.split("; ");
                    for (String userCookie : userCookies) {
                        String[] parts = userCookie.split("=", 2);
                        if (parts.length == 2) {
                            // Only modify if cookie already exists
                            if (cookieMap.containsKey(parts[0])) {
                                cookieMap.put(parts[0], parts[1]);
                                modified = true;
                            }
                        }
                    }
                }

                // Only update if modifications were made
                if (modified) {
                    String newCookieHeader = "Cookie: " + cookieMap.entrySet().stream()
                        .map(e -> e.getKey() + "=" + e.getValue())
                        .collect(Collectors.joining("; "));
                    headers.set(cookieHeaderIndex, newCookieHeader);
                }
            }
        }

        // Check if Authorization header exists and should be modified
        if (enableAuthorizationCheckBoxes[userIndex].isSelected() && 
            !authInputBoxes[userIndex].getText().trim().isEmpty()) {
            int authHeaderIndex = -1;
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).startsWith("Authorization:")) {
                    int headerStart = 0;
                    for (int j = 0; j < i; j++) {
                        headerStart += headers.get(j).length() + 2;
                    }
                    modDetails.authHighlights.add(new int[]{headerStart, headerStart + headers.get(i).length()});
                    authHeaderIndex = i;
                    break;
                }
            }
            // Only modify if Authorization header exists
            if (authHeaderIndex != -1) {
                String newAuthHeader = "Authorization: " + authInputBoxes[userIndex].getText().trim();
                headers.set(authHeaderIndex, newAuthHeader);
                modified = true;
            }
        }

        return modified ? helpers.buildHttpMessage(headers, body.getBytes()) : null;
    }

    private String generateRequestKey(IRequestInfo requestInfo, int userIndex) {
        String method = requestInfo.getMethod();
        String url = requestInfo.getUrl().toString();
        return method + ":" + url + ":" + userIndex;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("AutoRiseToTheOccasion");
        
        // Add immediate debug output
        callbacks.printOutput("Starting extension initialization...");

        SwingUtilities.invokeLater(() -> {
            try {
                callbacks.printOutput("Beginning UI setup...");
                mainPanel = new JPanel(new BorderLayout());
                tabbedPane = new JTabbedPane();
                
                int userCount = 10;
                int csrfTabIndex = userCount;
                int configTabIndex = userCount + 1;
                int totalTabs = userCount + 2;
                
                callbacks.printOutput("Creating arrays for " + totalTabs + " tabs");
                
                // Initialize arrays
                tables = new JTable[totalTabs];
                tableModels = new DefaultTableModel[totalTabs];
                requestViewers = new ITextEditor[totalTabs];
                modifiedRequestViewers = new ITextEditor[totalTabs];
                responseViewers = new ITextEditor[totalTabs];
                modifiedResponseViewers = new ITextEditor[totalTabs];
                roleCheckBoxes = new JCheckBox[userCount];
                enableCookiesCheckBoxes = new JCheckBox[userCount];
                enableAuthorizationCheckBoxes = new JCheckBox[userCount];
                cookieInputBoxes = new JTextField[userCount];
                authInputBoxes = new JTextField[userCount];

                // Create user tabs
                for (int i = 0; i < userCount; i++) {
                    callbacks.printOutput("Creating user tab " + i);
                    JPanel userPanel = new JPanel(new BorderLayout());
                    tableModels[i] = new DefaultTableModel(new Object[]{"ID", "Method", "URL", "Status", "Bypassed"}, 0);
                    tables[i] = new JTable(tableModels[i]);
                    adjustColumnWidths(tables[i]);
                    tables[i].getSelectionModel().addListSelectionListener(this);
                    
                    // Add custom cell renderer for the Bypassed column
                    tables[i].getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
                        @Override
                        public Component getTableCellRendererComponent(JTable table, Object value,
                                boolean isSelected, boolean hasFocus, int row, int column) {
                            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                            
                            if (value != null && value.toString().startsWith("Yes")) {
                                c.setBackground(new Color(144, 238, 144)); // Light green
                                c.setForeground(new Color(0, 100, 0));     // Dark green text
                            } else if (value != null && value.toString().startsWith("No")) {
                                c.setBackground(new Color(255, 180, 180)); // Darker red
                                c.setForeground(new Color(139, 0, 0));     // Dark red text
                            } else {
                                c.setBackground(table.getBackground());
                                c.setForeground(table.getForeground());
                            }
                            
                            if (isSelected) {
                                c.setForeground(table.getSelectionForeground());
                            }
                            
                            return c;
                        }
                    });

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

                    // Create tabbed panes for request and response viewers
                    JTabbedPane requestTabbedPane = new JTabbedPane();
                    requestTabbedPane.addTab("Original", new JScrollPane(requestViewers[i].getComponent()));
                    requestTabbedPane.addTab("Modified", new JScrollPane(modifiedRequestViewers[i].getComponent()));

                    JTabbedPane responseTabbedPane = new JTabbedPane();
                    responseTabbedPane.addTab("Original", new JScrollPane(responseViewers[i].getComponent()));
                    responseTabbedPane.addTab("Modified", new JScrollPane(modifiedResponseViewers[i].getComponent()));

                    // Create labeled panels
                    JPanel requestPanel = new JPanel(new BorderLayout());
                    requestPanel.add(new JLabel("Request"), BorderLayout.NORTH);
                    requestPanel.add(requestTabbedPane, BorderLayout.CENTER);

                    JPanel responsePanel = new JPanel(new BorderLayout());
                    responsePanel.add(new JLabel("Response"), BorderLayout.NORTH);
                    responsePanel.add(responseTabbedPane, BorderLayout.CENTER);

                    JSplitPane requestResponseSplitPane = new JSplitPane(
                        JSplitPane.VERTICAL_SPLIT,
                        requestPanel,
                        responsePanel
                    );
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

                callbacks.printOutput("Creating CSRF tab");
                // Create CSRF tab
                createCsrfTab(csrfTabIndex);
                
                callbacks.printOutput("Creating config tab");
                // Create config tab
                createConfigTab(configTabIndex);

                adjustRequestResponseBoxHeight();
                mainPanel.add(tabbedPane, BorderLayout.CENTER);
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(this);
                
                callbacks.printOutput("UI setup complete");
            } catch (Exception e) {
                callbacks.printError("Error during initialization: " + e.getMessage());
                e.printStackTrace(new PrintStream(callbacks.getStderr()));
            }
        });
    }

    private void createCsrfTab(int csrfTabIndex) {
        callbacks.printOutput("Setting up CSRF tab components");
        
        JPanel csrfPanel = new JPanel(new BorderLayout());
        tableModels[csrfTabIndex] = new DefaultTableModel(
            new Object[]{"ID", "Method", "URL", "Token Location", "Bypassed"}, 0);
        tables[csrfTabIndex] = new JTable(tableModels[csrfTabIndex]);
        adjustColumnWidths(tables[csrfTabIndex]);
        tables[csrfTabIndex].getSelectionModel().addListSelectionListener(this);

        requestViewers[csrfTabIndex] = callbacks.createTextEditor();
        modifiedRequestViewers[csrfTabIndex] = callbacks.createTextEditor();
        responseViewers[csrfTabIndex] = callbacks.createTextEditor();
        modifiedResponseViewers[csrfTabIndex] = callbacks.createTextEditor();

        JTabbedPane csrfRequestTabbedPane = new JTabbedPane();
        csrfRequestTabbedPane.addTab("Original", new JScrollPane(requestViewers[csrfTabIndex].getComponent()));
        csrfRequestTabbedPane.addTab("Modified", new JScrollPane(modifiedRequestViewers[csrfTabIndex].getComponent()));

        JTabbedPane csrfResponseTabbedPane = new JTabbedPane();
        csrfResponseTabbedPane.addTab("Original", new JScrollPane(responseViewers[csrfTabIndex].getComponent()));
        csrfResponseTabbedPane.addTab("Modified", new JScrollPane(modifiedResponseViewers[csrfTabIndex].getComponent()));

        JPanel csrfRequestPanel = new JPanel(new BorderLayout());
        csrfRequestPanel.add(new JLabel("Request"), BorderLayout.NORTH);
        csrfRequestPanel.add(csrfRequestTabbedPane, BorderLayout.CENTER);

        JPanel csrfResponsePanel = new JPanel(new BorderLayout());
        csrfResponsePanel.add(new JLabel("Response"), BorderLayout.NORTH);
        csrfResponsePanel.add(csrfResponseTabbedPane, BorderLayout.CENTER);

        JSplitPane csrfRequestResponseSplitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            csrfRequestPanel,
            csrfResponsePanel
        );
        csrfRequestResponseSplitPane.setResizeWeight(0.5);

        JSplitPane csrfMainSplitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT, 
            new JScrollPane(tables[csrfTabIndex]), 
            csrfRequestResponseSplitPane
        );
        csrfMainSplitPane.setResizeWeight(0.33);

        csrfPanel.add(csrfMainSplitPane, BorderLayout.CENTER);
        
        callbacks.printOutput("Adding CSRF tab to tabbedPane");
        tabbedPane.addTab("CSRF Tests", csrfPanel);

        callbacks.printOutput("Registering CSRF HTTP listener");
        callbacks.registerHttpListener(new AutoRiseHttpListener(this, csrfTabIndex));
    }

    private void createConfigTab(int configTabIndex) {
        callbacks.printOutput("Setting up Config tab components");
        
        JPanel configPanel = new JPanel(new BorderLayout());
        
        // Create CSRF test checkbox
        csrfTestCheckBox = new JCheckBox("Enable CSRF Testing");
        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setBorder(BorderFactory.createTitledBorder("Configuration Options"));
        checkboxPanel.add(csrfTestCheckBox);
        
        configPanel.add(checkboxPanel, BorderLayout.NORTH);
        
        // Initialize table components for config tab
        tableModels[configTabIndex] = new DefaultTableModel(
            new Object[]{"ID", "Method", "URL", "Status", "Configuration"}, 0);
        tables[configTabIndex] = new JTable(tableModels[configTabIndex]);
        adjustColumnWidths(tables[configTabIndex]);
        
        // Initialize text editors
        requestViewers[configTabIndex] = callbacks.createTextEditor();
        modifiedRequestViewers[configTabIndex] = callbacks.createTextEditor();
        responseViewers[configTabIndex] = callbacks.createTextEditor();
        modifiedResponseViewers[configTabIndex] = callbacks.createTextEditor();
        
        // Add to tabbedPane
        tabbedPane.addTab("Configuration", configPanel);
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo, int userIndex) {
        // Skip if not from proxy tool
        if (toolFlag != callbacks.TOOL_PROXY) {
            return;
        }
        
        // Only process messages when it's a response
        if (!messageIsRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            String requestKey = generateRequestKey(requestInfo, userIndex);

            synchronized (lock) {
                // Skip if already processed
                if (processedRequestKeys.contains(requestKey)) {
                    return;
                }
                processedRequestKeys.add(requestKey);
                
                // For CSRF tab (userIndex == 10), check if CSRF testing is enabled
                if (userIndex == 10) {
                    if (!csrfTestCheckBox.isSelected()) {
                        return;
                    }
                } else if (userIndex < 10 && !roleCheckBoxes[userIndex].isSelected()) {
                    // Skip if role is not enabled for regular user tabs
                    return;
                }

                int id = requestCounter++;
                byte[] originalRequest = messageInfo.getRequest();
                byte[] originalResponse = messageInfo.getResponse();
                byte[] modifiedRequest = null;
                IHttpRequestResponse modifiedMessage = null;
                boolean modificationsAttempted = false;

                // Handle CSRF modifications differently
                if (userIndex == 10) {
                    modifiedRequest = modifyCsrfToken(originalRequest);
                    if (modifiedRequest != null) {
                        modificationsAttempted = true;
                        modifiedMessage = callbacks.makeHttpRequest(
                            messageInfo.getHttpService(),
                            modifiedRequest
                        );
                    }
                } else if (enableCookiesCheckBoxes[userIndex].isSelected() || 
                    enableAuthorizationCheckBoxes[userIndex].isSelected()) {
                    // Handle regular role-based modifications
                    modifiedRequest = modifyRequest(originalRequest, userIndex, String.valueOf(id));
                    if (!Arrays.equals(originalRequest, modifiedRequest)) {
                        modificationsAttempted = true;
                        modifiedMessage = callbacks.makeHttpRequest(
                            messageInfo.getHttpService(),
                            modifiedRequest
                        );
                    }
                }

                // Store in request response map
                RequestResponsePair pair = new RequestResponsePair();
                pair.id = id;
                pair.originalRequest = originalRequest;
                pair.modifiedRequest = modifiedRequest;
                pair.originalResponse = originalResponse;
                pair.modifiedResponse = modifiedMessage != null ? modifiedMessage.getResponse() : null;
                requestResponseMap.put(id, pair);

                // Determine bypass status
                String bypassStatus;
                if (!modificationsAttempted) {
                    bypassStatus = "No modifications attempted";
                } else if (modifiedMessage != null && 
                         helpers.analyzeResponse(modifiedMessage.getResponse()).getStatusCode() == 200) {
                    bypassStatus = userIndex == 10 ? "Yes - CSRF bypass successful" : "Yes - Role bypass successful";
                } else {
                    bypassStatus = userIndex == 10 ? "No - CSRF bypass failed" : "No - Modifications failed";
                }

                final String finalBypassStatus = bypassStatus;
                final int finalId = id;
                final IHttpRequestResponse finalModifiedMessage = modifiedMessage != null ? modifiedMessage : messageInfo;

                SwingUtilities.invokeLater(() -> {
                    try {
                        if (userIndex == 10) {
                            // For CSRF tab, include token location
                            tableModels[userIndex].addRow(new Object[]{
                                finalId,
                                requestInfo.getMethod(),
                                requestInfo.getUrl().toString(),
                                getCsrfTokenLocation(messageInfo),
                                finalBypassStatus
                            });
                        } else {
                            tableModels[userIndex].addRow(new Object[]{
                                finalId,
                                requestInfo.getMethod(),
                                requestInfo.getUrl().toString(),
                                helpers.analyzeResponse(finalModifiedMessage.getResponse()).getStatusCode(),
                                finalBypassStatus
                            });
                        }
                    } catch (Exception e) {
                        logError("Error adding row to table: " + e.getMessage());
                        e.printStackTrace(new PrintStream(callbacks.getStderr()));
                    }
                });
            }
        }
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        if (!e.getValueIsAdjusting()) {
            for (int i = 0; i < tables.length; i++) {
                JTable table = tables[i];
                if (e.getSource() == table.getSelectionModel()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow >= 0) {
                        int id = (int) tableModels[i].getValueAt(selectedRow, 0);
                        RequestResponsePair pair = requestResponseMap.get(id);
                        ModificationDetails modDetails = highlightMap.get(id);
                        
                        if (pair != null) {
                            final int viewerIndex = i;
                            SwingUtilities.invokeLater(() -> {
                                // Clear existing highlights
                                requestViewers[viewerIndex].setSearchExpression(null);
                                modifiedRequestViewers[viewerIndex].setSearchExpression(null);
                                
                                requestViewers[viewerIndex].setText(pair.originalRequest);
                                responseViewers[viewerIndex].setText(pair.originalResponse);
                                
                                if (pair.modifiedRequest != null && pair.modifiedResponse != null) {
                                    modifiedRequestViewers[viewerIndex].setText(pair.modifiedRequest);
                                    modifiedResponseViewers[viewerIndex].setText(pair.modifiedResponse);
                                    
                                    // Apply highlights to modified request
                                    if (modDetails != null) {
                                        for (int[] highlight : modDetails.cookieHighlights) {
                                            String text = new String(modifiedRequestViewers[viewerIndex].getText());
                                            String highlightText = text.substring(highlight[0], highlight[1]);
                                            modifiedRequestViewers[viewerIndex].setSearchExpression(highlightText);
                                        }
                                        for (int[] highlight : modDetails.authHighlights) {
                                            String text = new String(modifiedRequestViewers[viewerIndex].getText());
                                            String highlightText = text.substring(highlight[0], highlight[1]);
                                            modifiedRequestViewers[viewerIndex].setSearchExpression(highlightText);
                                        }
                                    }
                                } else {
                                    modifiedRequestViewers[viewerIndex].setText("No modifications were made to this request".getBytes());
                                    modifiedResponseViewers[viewerIndex].setText("No modified response available".getBytes());
                                }
                            });
                        }
                    }
                    break;
                }
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

    private byte[] modifyCsrfToken(byte[] request) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(request).substring(requestInfo.getBodyOffset());
        
        boolean modified = false;
        List<String> modifiedHeaders = new ArrayList<>(headers);
        
        // Check headers for CSRF tokens
        for (int i = 0; i < modifiedHeaders.size(); i++) {
            String header = modifiedHeaders.get(i).toLowerCase();
            if (header.contains("csrf") || header.contains("xsrf")) {
                String[] parts = modifiedHeaders.get(i).split(": ", 2);
                if (parts.length == 2) {
                    // Try different CSRF bypass techniques
                    String modifiedValue = parts[1] + "_bypass"; // Simple modification
                    modifiedHeaders.set(i, parts[0] + ": " + modifiedValue);
                    modified = true;
                }
            }
        }
        
        // Check and modify CSRF tokens in cookies
        for (int i = 0; i < modifiedHeaders.size(); i++) {
            String header = modifiedHeaders.get(i);
            if (header.toLowerCase().startsWith("cookie:")) {
                String[] cookies = header.substring(8).split("; ");
                List<String> modifiedCookies = new ArrayList<>();
                
                for (String cookie : cookies) {
                    if (cookie.toLowerCase().contains("csrf") || cookie.toLowerCase().contains("xsrf")) {
                        String[] parts = cookie.split("=", 2);
                        if (parts.length == 2) {
                            modifiedCookies.add(parts[0] + "=" + parts[1] + "_bypass");
                            modified = true;
                        } else {
                            modifiedCookies.add(cookie);
                        }
                    } else {
                        modifiedCookies.add(cookie);
                    }
                }
                
                modifiedHeaders.set(i, "Cookie: " + String.join("; ", modifiedCookies));
            }
        }
        
        // Check body for CSRF tokens
        String modifiedBody = body;
        if (body.contains("csrf") || body.contains("xsrf")) {
            // More sophisticated token detection and modification
            modifiedBody = body.replaceAll("(csrf[^=]+=)([^&\n]+)", "$1$2_bypass")
                             .replaceAll("(xsrf[^=]+=)([^&\n]+)", "$1$2_bypass");
            modified = true;
        }
        
        return modified ? helpers.buildHttpMessage(modifiedHeaders, modifiedBody.getBytes()) : null;
    }

    private boolean hasCsrfTokens(IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(messageInfo.getRequest()).substring(requestInfo.getBodyOffset());

        // Check common CSRF token patterns in headers
        boolean hasCSRFHeader = headers.stream().anyMatch(h -> 
            h.toLowerCase().contains("csrf") || 
            h.toLowerCase().contains("xsrf") || 
            h.toLowerCase().contains("anti-forgery")
        );

        // Check for CSRF tokens in cookies
        boolean hasCSRFCookie = headers.stream()
            .filter(h -> h.toLowerCase().startsWith("cookie:"))
            .anyMatch(c -> 
                c.toLowerCase().contains("csrf") || 
                c.toLowerCase().contains("xsrf") || 
                c.toLowerCase().contains("anti-forgery")
            );

        // Check for common CSRF token patterns in body
        boolean hasCSRFBody = body.toLowerCase().contains("csrf") || 
                            body.toLowerCase().contains("xsrf") || 
                            body.toLowerCase().contains("anti-forgery");

        return hasCSRFHeader || hasCSRFCookie || hasCSRFBody;
    }

    private String getCsrfTokenLocation(IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(messageInfo.getRequest()).substring(requestInfo.getBodyOffset());
        List<String> locations = new ArrayList<>();

        if (headers.stream().anyMatch(h -> h.toLowerCase().contains("csrf") || 
                                         h.toLowerCase().contains("xsrf"))) {
            locations.add("Header");
        }
        if (headers.stream()
                  .filter(h -> h.toLowerCase().startsWith("cookie:"))
                  .anyMatch(c -> c.toLowerCase().contains("csrf") || 
                                c.toLowerCase().contains("xsrf"))) {
            locations.add("Cookie");
        }
        if (body.toLowerCase().contains("csrf") || body.toLowerCase().contains("xsrf")) {
            locations.add("Body");
        }

        return String.join(", ", locations);
    }
}