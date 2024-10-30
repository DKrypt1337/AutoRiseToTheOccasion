import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
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
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.ITab;
import burp.ITextEditor;

public class AutoRiseToTheOccasion implements IBurpExtender, ITab, ListSelectionListener, IContextMenuFactory {
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
    private JButton exportCsrfReportButton;
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

    private JPopupMenu tablePopupMenu;
    private JPopupMenu requestViewerPopupMenu;

    // At the class level, initialize the checkbox
    private final JCheckBox csrfTestCheckBox = new JCheckBox("Enable CSRF Testing");

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
        IHttpService httpService;
    }

    // Update the modifyRequest method to track modification positions
    private byte[] modifyRequest(byte[] request, int userIndex, String requestId) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(request).substring(requestInfo.getBodyOffset());

        ModificationDetails modDetails = new ModificationDetails();
        highlightMap.put(Integer.valueOf(requestId), modDetails);

        boolean modified = false;
        
        // Check and modify Cookie header if enabled
        if (enableCookiesCheckBoxes[userIndex].isSelected() && !cookieInputBoxes[userIndex].getText().trim().isEmpty()) {
            int cookieHeaderIndex = -1;
            String cookieHeader = null;
            
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).toLowerCase().startsWith("cookie:")) {
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
                            // Case-insensitive cookie name comparison
                            String userCookieName = parts[0];
                            Optional<String> matchingCookie = cookieMap.keySet().stream()
                                .filter(existingName -> existingName.equalsIgnoreCase(userCookieName))
                                .findFirst();
                            
                            if (matchingCookie.isPresent()) {
                                cookieMap.put(matchingCookie.get(), parts[1]);
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

        // Check and modify Authorization header if enabled
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
                
                // Initialize arrays and UI components
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

                // Initialize checkboxes and text fields
                for (int i = 0; i < userCount; i++) {
                    roleCheckBoxes[i] = new JCheckBox("Enable Role " + (i + 1));
                    enableCookiesCheckBoxes[i] = new JCheckBox("Enable Cookies");
                    enableAuthorizationCheckBoxes[i] = new JCheckBox("Enable Authorization");
                    cookieInputBoxes[i] = new JTextField(20);
                    authInputBoxes[i] = new JTextField(20);
                }

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
                            } else if (value != null && value.toString().equals("No modifications attempted")) {
                                c.setBackground(new Color(69, 69, 69));    // Dark grey
                                c.setForeground(Color.WHITE);              // White text
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

                    JSplitPane mainSplitPane = new JSplitPane(
                        JSplitPane.VERTICAL_SPLIT, 
                        new JScrollPane(tables[i]), 
                        requestResponseSplitPane
                    );
                    mainSplitPane.setResizeWeight(0.33);

                    userPanel.add(mainSplitPane, BorderLayout.CENTER);
                    tabbedPane.addTab("User " + (i + 1), userPanel);

                    callbacks.registerHttpListener(new AutoRiseHttpListener(this, i));
                }

                callbacks.printOutput("Creating CSRF tab");
                createCsrfTab(csrfTabIndex);
                
                callbacks.printOutput("Creating config tab");
                createConfigTab(configTabIndex);

                adjustRequestResponseBoxHeight();
                mainPanel.add(tabbedPane, BorderLayout.CENTER);
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(this);
                
                callbacks.printOutput("UI setup complete");

                callbacks.registerContextMenuFactory(this);
                setupContextMenus();
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

        // Add custom cell renderer for the Bypassed column
        tables[csrfTabIndex].getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (value != null) {
                    String status = value.toString();
                    if (status.contains("successful")) {
                        c.setBackground(new Color(144, 238, 144)); // Light green
                        c.setForeground(new Color(0, 100, 0));     // Dark green text
                    } else if (status.contains("failed")) {
                        c.setBackground(new Color(255, 180, 180)); // Light red
                        c.setForeground(new Color(139, 0, 0));     // Dark red text
                    } else if (status.equals("No modifications attempted")) {
                        c.setBackground(new Color(69, 69, 69));    // Dark grey
                        c.setForeground(Color.WHITE);              // White text
                    } else {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }
                
                if (isSelected) {
                    c.setForeground(table.getSelectionForeground());
                }
                
                return c;
            }
        });

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
        
        // Create main configuration panel with vertical BoxLayout
        JPanel mainConfigPanel = new JPanel();
        mainConfigPanel.setLayout(new BoxLayout(mainConfigPanel, BoxLayout.Y_AXIS));
        mainConfigPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // CSRF Configuration Section
        JPanel csrfPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        csrfPanel.setBorder(BorderFactory.createTitledBorder("CSRF Testing Configuration"));
        csrfPanel.add(csrfTestCheckBox);
        
        exportCsrfReportButton = new JButton("Export CSRF Report");
        exportCsrfReportButton.addActionListener(e -> exportCsrfReport());
        csrfPanel.add(exportCsrfReportButton);
        
        mainConfigPanel.add(csrfPanel);
        mainConfigPanel.add(Box.createVerticalStrut(10));

        // User Configurations Section
        JPanel usersPanel = new JPanel();
        usersPanel.setLayout(new BoxLayout(usersPanel, BoxLayout.Y_AXIS));
        usersPanel.setBorder(BorderFactory.createTitledBorder("User Configurations"));

        for (int i = 0; i < roleCheckBoxes.length; i++) {
            JPanel userPanel = new JPanel();
            userPanel.setLayout(new BoxLayout(userPanel, BoxLayout.Y_AXIS));
            userPanel.setBorder(BorderFactory.createTitledBorder("User " + (i + 1)));

            // Enable role checkbox
            JPanel rolePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            rolePanel.add(roleCheckBoxes[i]);
            userPanel.add(rolePanel);

            // Cookie configuration
            JPanel cookiePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            cookiePanel.add(enableCookiesCheckBoxes[i]);
            cookiePanel.add(new JLabel("Cookie Value:"));
            cookieInputBoxes[i].setPreferredSize(new Dimension(300, 25));
            cookiePanel.add(cookieInputBoxes[i]);
            userPanel.add(cookiePanel);

            // Authorization configuration
            JPanel authPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            authPanel.add(enableAuthorizationCheckBoxes[i]);
            authPanel.add(new JLabel("Authorization Value:"));
            authInputBoxes[i].setPreferredSize(new Dimension(300, 25));
            authPanel.add(authInputBoxes[i]);
            userPanel.add(authPanel);

            // Add separator except for last user
            if (i < roleCheckBoxes.length - 1) {
                userPanel.add(Box.createVerticalStrut(5));
                userPanel.add(new JSeparator(JSeparator.HORIZONTAL));
                userPanel.add(Box.createVerticalStrut(5));
            }

            usersPanel.add(userPanel);
        }

        // Add users panel to a scroll pane with improved scroll settings
        JScrollPane scrollPane = new JScrollPane(mainConfigPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getViewport().setBackground(mainConfigPanel.getBackground());
        
        // Enable mouse wheel scrolling
        scrollPane.addMouseWheelListener(e -> {
            int notches = e.getWheelRotation();
            JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
            int newValue = verticalScrollBar.getValue() + (notches * verticalScrollBar.getUnitIncrement());
            verticalScrollBar.setValue(newValue);
        });

        mainConfigPanel.add(usersPanel);

        // Add scroll pane to config panel
        configPanel.add(scrollPane, BorderLayout.CENTER);
        
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
                    if (csrfTestCheckBox == null || !csrfTestCheckBox.isSelected()) {
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
                    Object modifiedRequests = modifyCsrfToken(originalRequest);
                    if (modifiedRequests != null) {
                        modificationsAttempted = true;
                        
                        if (modifiedRequests instanceof byte[][]) {
                            // We have both cookie and header modifications
                            byte[][] requests = (byte[][])modifiedRequests;
                            
                            // First request: Cookie modified
                            IHttpRequestResponse cookieModifiedMessage = callbacks.makeHttpRequest(
                                messageInfo.getHttpService(),
                                requests[0]
                            );
                            
                            // Second request: Header modified
                            IHttpRequestResponse headerModifiedMessage = callbacks.makeHttpRequest(
                                messageInfo.getHttpService(),
                                requests[1]
                            );
                            
                            // Store both modified requests and responses
                            RequestResponsePair pair = new RequestResponsePair();
                            pair.id = id;
                            pair.originalRequest = originalRequest;
                            pair.originalResponse = originalResponse;
                            pair.modifiedRequest = requests[0]; // Store cookie-modified request
                            pair.modifiedResponse = cookieModifiedMessage.getResponse();
                            pair.httpService = messageInfo.getHttpService();
                            requestResponseMap.put(id, pair);
                            
                            // Create new entry for header-modified request
                            int headerId = requestCounter++;
                            RequestResponsePair headerPair = new RequestResponsePair();
                            headerPair.id = headerId;
                            headerPair.originalRequest = originalRequest;
                            headerPair.originalResponse = originalResponse;
                            headerPair.modifiedRequest = requests[1];
                            headerPair.modifiedResponse = headerModifiedMessage.getResponse();
                            headerPair.httpService = messageInfo.getHttpService();
                            requestResponseMap.put(headerId, headerPair);
                            
                            // Add both entries to the table
                            final int finalId = id;
                            final int finalHeaderId = headerId;
                            SwingUtilities.invokeLater(() -> {
                                try {
                                    // Add cookie-modified request entry
                                    tableModels[userIndex].addRow(new Object[]{
                                        finalId,
                                        requestInfo.getMethod(),
                                        requestInfo.getUrl().toString() + " (Cookie Modified)",
                                        getCsrfTokenLocation(messageInfo),
                                        helpers.analyzeResponse(cookieModifiedMessage.getResponse()).getStatusCode() == 200 
                                            ? "Yes - CSRF bypass successful (Cookie)" 
                                            : "No - CSRF bypass failed (Cookie)"
                                    });
                                    
                                    // Add header-modified request entry
                                    tableModels[userIndex].addRow(new Object[]{
                                        finalHeaderId,
                                        requestInfo.getMethod(),
                                        requestInfo.getUrl().toString() + " (Header Modified)",
                                        getCsrfTokenLocation(messageInfo),
                                        helpers.analyzeResponse(headerModifiedMessage.getResponse()).getStatusCode() == 200 
                                            ? "Yes - CSRF bypass successful (Header)" 
                                            : "No - CSRF bypass failed (Header)"
                                    });
                                } catch (Exception e) {
                                    logError("Error adding rows to table: " + e.getMessage());
                                    e.printStackTrace(new PrintStream(callbacks.getStderr()));
                                }
                            });
                            return;
                        } else {
                            // Single modification case
                            modifiedRequest = (byte[])modifiedRequests;
                            modifiedMessage = callbacks.makeHttpRequest(
                                messageInfo.getHttpService(),
                                modifiedRequest
                            );
                        }
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

                // Store in request response map (for single modification cases)
                RequestResponsePair pair = new RequestResponsePair();
                pair.id = id;
                pair.originalRequest = originalRequest;
                pair.modifiedRequest = modifiedRequest;
                pair.originalResponse = originalResponse;
                pair.modifiedResponse = modifiedMessage != null ? modifiedMessage.getResponse() : null;
                pair.httpService = messageInfo.getHttpService();
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

    private Object modifyCsrfToken(byte[] request) {
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        String body = new String(request).substring(requestInfo.getBodyOffset());
        
        List<String> modifiedHeaders = new ArrayList<>(headers);
        
        // Specific CSRF token patterns
        List<String> csrfPatterns = Arrays.asList(
            "x-csrf-token",
            "x-xsrf-token",
            "csrf-token",
            "xsrf-token",
            "x-csrf",
            "x-xsrf",
            "_csrf",
            "_xsrf",
            "anti-forgery-token",
            "x-anti-forgery-token",
            "__requestverificationtoken",
            "authenticity_token",
            "csrf_nonce",
            "csrf-key",
            "x-csrf-header",
            "x-csrf-protection",
            "csrftoken",
            "csrf_token",
            "xsrftoken",
            "xsrf_token"
        );
        
        // Find CSRF tokens in headers and cookies
        int csrfHeaderIndex = -1;
        int csrfCookieIndex = -1;
        String csrfCookieName = null;
        boolean foundCsrfHeader = false;
        
        // Check headers
        for (int i = 0; i < modifiedHeaders.size(); i++) {
            String header = modifiedHeaders.get(i);
            String[] headerParts = header.split(":", 2);
            if (headerParts.length > 0) {
                String headerName = headerParts[0].toLowerCase().trim();
                // Check if any CSRF pattern matches the header name only
                if (csrfPatterns.stream().anyMatch(pattern -> headerName.contains(pattern.toLowerCase()))) {
                    csrfHeaderIndex = i;
                    foundCsrfHeader = true;
                }
                if (headerName.equals("cookie")) {
                    String[] cookies = headerParts.length > 1 ? headerParts[1].trim().split("; ") : new String[0];
                    for (String cookie : cookies) {
                        String cookieName = cookie.split("=", 2)[0].toLowerCase();
                        if (csrfPatterns.stream().anyMatch(pattern -> cookieName.contains(pattern.toLowerCase()))) {
                            csrfCookieIndex = i;
                            csrfCookieName = cookie.split("=")[0];
                            break;
                        }
                    }
                }
            }
        }
        
        // If no CSRF header is found, don't attempt header modification
        if (!foundCsrfHeader) {
            // Only return cookie modification if a CSRF cookie exists
            if (csrfCookieIndex != -1) {
                String cookieHeader = modifiedHeaders.get(csrfCookieIndex);
                String[] cookies = cookieHeader.substring(8).split("; ");
                List<String> modifiedCookies = new ArrayList<>();
                
                for (String cookie : cookies) {
                    if (cookie.startsWith(csrfCookieName)) {
                        String[] parts = cookie.split("=", 2);
                        if (parts.length == 2) {
                            modifiedCookies.add(parts[0] + "=" + modifyTokenValue(parts[1]));
                        }
                    } else {
                        modifiedCookies.add(cookie);
                    }
                }
                modifiedHeaders.set(csrfCookieIndex, "Cookie: " + String.join("; ", modifiedCookies));
                return helpers.buildHttpMessage(modifiedHeaders, body.getBytes());
            }
            return null;
        }
        
        // If both header and cookie CSRF tokens exist, create two different requests
        if (csrfHeaderIndex != -1 && csrfCookieIndex != -1) {
            // First request: Modify cookie, keep header original
            List<String> cookieModifiedHeaders = new ArrayList<>(headers);
            String cookieHeader = cookieModifiedHeaders.get(csrfCookieIndex);
            String[] cookies = cookieHeader.substring(8).split("; ");
            List<String> modifiedCookies = new ArrayList<>();
            
            for (String cookie : cookies) {
                if (cookie.startsWith(csrfCookieName)) {
                    String[] parts = cookie.split("=", 2);
                    if (parts.length == 2) {
                        modifiedCookies.add(parts[0] + "=" + modifyTokenValue(parts[1]));
                    }
                } else {
                    modifiedCookies.add(cookie);
                }
            }
            cookieModifiedHeaders.set(csrfCookieIndex, "Cookie: " + String.join("; ", modifiedCookies));
            byte[] cookieModifiedRequest = helpers.buildHttpMessage(cookieModifiedHeaders, body.getBytes());
            
            // Second request: Modify header, keep cookie original
            List<String> headerModifiedHeaders = new ArrayList<>(headers);
            String[] headerParts = headerModifiedHeaders.get(csrfHeaderIndex).split(": ", 2);
            if (headerParts.length == 2) {
                headerModifiedHeaders.set(csrfHeaderIndex, headerParts[0] + ": " + modifyTokenValue(headerParts[1]));
            }
            byte[] headerModifiedRequest = helpers.buildHttpMessage(headerModifiedHeaders, body.getBytes());
            
            // Return both modified requests as an array
            return new byte[][] { cookieModifiedRequest, headerModifiedRequest };
        }
        
        // If only one type of token exists, modify it
        boolean modified = false;
        
        // Modify header if it exists
        if (csrfHeaderIndex != -1) {
            String[] parts = modifiedHeaders.get(csrfHeaderIndex).split(": ", 2);
            if (parts.length == 2) {
                modifiedHeaders.set(csrfHeaderIndex, parts[0] + ": " + modifyTokenValue(parts[1]));
                modified = true;
            }
        }
        
        // Modify cookie if it exists
        if (csrfCookieIndex != -1) {
            String cookieHeader = modifiedHeaders.get(csrfCookieIndex);
            String[] cookies = cookieHeader.substring(8).split("; ");
            List<String> modifiedCookies = new ArrayList<>();
            
            for (String cookie : cookies) {
                boolean isCsrfCookie = csrfPatterns.stream()
                    .anyMatch(pattern -> cookie.toLowerCase().contains(pattern));
                
                if (isCsrfCookie) {
                    String[] parts = cookie.split("=", 2);
                    if (parts.length == 2) {
                        modifiedCookies.add(parts[0] + "=" + modifyTokenValue(parts[1]));
                        modified = true;
                    } else {
                        modifiedCookies.add(cookie);
                    }
                } else {
                    modifiedCookies.add(cookie);
                }
            }
            
            modifiedHeaders.set(csrfCookieIndex, "Cookie: " + String.join("; ", modifiedCookies));
        }
        
        // Check body for CSRF tokens
        String modifiedBody = body;
        for (String pattern : csrfPatterns) {
            if (body.toLowerCase().contains(pattern)) {
                String regex = "(" + pattern + "[^=]+=)([^&\\n\"]+)";
                modifiedBody = modifiedBody.replaceAll(regex, "$1$2_bypass");
                modified = true;
            }
        }
        
        return modified ? helpers.buildHttpMessage(modifiedHeaders, modifiedBody.getBytes()) : null;
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

    private void setupContextMenus() {
        // Setup table context menu
        for (int i = 0; i < tables.length; i++) {
            final int tabIndex = i;
            tables[i].addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = tables[tabIndex].rowAtPoint(e.getPoint());
                        if (row >= 0) {
                            tables[tabIndex].setRowSelectionInterval(row, row);
                            showTableContextMenu(e, tabIndex, row);
                        }
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = tables[tabIndex].rowAtPoint(e.getPoint());
                        if (row >= 0) {
                            tables[tabIndex].setRowSelectionInterval(row, row);
                            showTableContextMenu(e, tabIndex, row);
                        }
                    }
                }
            });

            // Setup request viewer context menu only
            requestViewers[i].getComponent().addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRequestViewerContextMenu(e, tabIndex, true, false);
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRequestViewerContextMenu(e, tabIndex, true, false);
                    }
                }
            });

            modifiedRequestViewers[i].getComponent().addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRequestViewerContextMenu(e, tabIndex, true, true);
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRequestViewerContextMenu(e, tabIndex, true, true);
                    }
                }
            });
        }
    }

    private void showTableContextMenu(MouseEvent e, int tabIndex, int row) {
        JPopupMenu menu = new JPopupMenu();
        int id = (int) tableModels[tabIndex].getValueAt(row, 0);
        RequestResponsePair pair = requestResponseMap.get(id);
        
        if (pair != null && pair.httpService != null) {
            JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
            sendToRepeater.addActionListener(ev -> {
                try {
                    callbacks.printOutput("Sending to Repeater - ID: " + id);
                    callbacks.sendToRepeater(
                        pair.httpService.getHost(),
                        pair.httpService.getPort(),
                        pair.httpService.getProtocol().equalsIgnoreCase("https"),
                        pair.originalRequest,
                        "AutoRise #" + id
                    );
                } catch (Exception ex) {
                    callbacks.printError("Error sending to Repeater: " + ex.getMessage());
                    ex.printStackTrace(new PrintStream(callbacks.getStderr()));
                }
            });
            menu.add(sendToRepeater);

            JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
            sendToIntruder.addActionListener(ev -> {
                try {
                    callbacks.printOutput("Sending to Intruder - ID: " + id);
                    callbacks.sendToIntruder(
                        pair.httpService.getHost(),
                        pair.httpService.getPort(),
                        pair.httpService.getProtocol().equalsIgnoreCase("https"),
                        pair.originalRequest
                    );
                } catch (Exception ex) {
                    callbacks.printError("Error sending to Intruder: " + ex.getMessage());
                    ex.printStackTrace(new PrintStream(callbacks.getStderr()));
                }
            });
            menu.add(sendToIntruder);

            menu.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    private void showRequestViewerContextMenu(MouseEvent e, int tabIndex, boolean isRequest, boolean isModified) {
        int row = tables[tabIndex].getSelectedRow();
        if (row >= 0) {
            int id = (int) tableModels[tabIndex].getValueAt(row, 0);
            RequestResponsePair pair = requestResponseMap.get(id);
            
            if (pair != null && pair.httpService != null) {
                JPopupMenu menu = new JPopupMenu();
                
                JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
                sendToRepeater.addActionListener(ev -> {
                    try {
                        byte[] content = isRequest ? 
                            (isModified ? pair.modifiedRequest : pair.originalRequest) :
                            (isModified ? pair.modifiedResponse : pair.originalResponse);
                        
                        callbacks.sendToRepeater(
                            pair.httpService.getHost(),
                            pair.httpService.getPort(),
                            pair.httpService.getProtocol().equalsIgnoreCase("https"),
                            content,
                            "AutoRise #" + id + (isModified ? " (Modified)" : "")
                        );
                    } catch (Exception ex) {
                        callbacks.printError("Error sending to Repeater: " + ex.getMessage());
                        ex.printStackTrace(new PrintStream(callbacks.getStderr()));
                    }
                });
                menu.add(sendToRepeater);

                if (isRequest) {
                    JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
                    sendToIntruder.addActionListener(ev -> {
                        try {
                            byte[] content = isModified ? pair.modifiedRequest : pair.originalRequest;
                            callbacks.sendToIntruder(
                                pair.httpService.getHost(),
                                pair.httpService.getPort(),
                                pair.httpService.getProtocol().equalsIgnoreCase("https"),
                                content
                            );
                        } catch (Exception ex) {
                            callbacks.printError("Error sending to Intruder: " + ex.getMessage());
                            ex.printStackTrace(new PrintStream(callbacks.getStderr()));
                        }
                    });
                    menu.add(sendToIntruder);
                }

                menu.show(e.getComponent(), e.getX(), e.getY());
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return null; // We're handling our own context menus
    }

    private String modifyTokenValue(String originalValue) {
        if (originalValue == null || originalValue.isEmpty()) {
            return originalValue;
        }
        
        // Remove last character and replace with a different one
        char lastChar = originalValue.charAt(originalValue.length() - 1);
        char replacementChar;
        
        // Choose a replacement that's different from the original
        if (Character.isDigit(lastChar)) {
            // If it's a number, replace with a different number
            replacementChar = (char)('0' + ((lastChar - '0' + 1) % 10));
        } else if (Character.isLetter(lastChar)) {
            // If it's a letter, replace with a different letter
            replacementChar = (char)('a' + ((lastChar - 'a' + 1) % 26));
        } else {
            // For special characters, use 'x'
            replacementChar = 'x';
        }
        
        return originalValue.substring(0, originalValue.length() - 1) + replacementChar;
    }

    private void exportCsrfReport() {
        try {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save CSRF Report");
            fileChooser.setSelectedFile(new File("csrf_report.txt"));
            
            if (fileChooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                
                // Collect data
                Set<String> cookieUrls = new HashSet<>();
                Set<String> headerUrls = new HashSet<>();
                Set<String> bothUrls = new HashSet<>();
                Set<String> bypassedCookieUrls = new HashSet<>();
                Set<String> bypassedHeaderUrls = new HashSet<>();
                Set<String> failedCookieUrls = new HashSet<>();
                Set<String> failedHeaderUrls = new HashSet<>();
                Set<String> failedBothUrls = new HashSet<>();
                
                // Get data from CSRF tab (index 10)
                DefaultTableModel model = tableModels[10];
                for (int i = 0; i < model.getRowCount(); i++) {
                    String url = (String) model.getValueAt(i, 2);
                    String location = (String) model.getValueAt(i, 3);
                    String bypassed = (String) model.getValueAt(i, 4);
                    
                    // Categorize by location
                    if (location.contains("Cookie") && location.contains("Header")) {
                        bothUrls.add(url);
                        if (bypassed.contains("successful")) {
                            bypassedCookieUrls.add(url);
                            bypassedHeaderUrls.add(url);
                        } else if (bypassed.contains("failed")) {
                            failedBothUrls.add(url);
                        }
                    } else if (location.contains("Cookie")) {
                        cookieUrls.add(url);
                        if (bypassed.contains("successful")) {
                            bypassedCookieUrls.add(url);
                        } else if (bypassed.contains("failed")) {
                            failedCookieUrls.add(url);
                        }
                    } else if (location.contains("Header")) {
                        headerUrls.add(url);
                        if (bypassed.contains("successful")) {
                            bypassedHeaderUrls.add(url);
                        } else if (bypassed.contains("failed")) {
                            failedHeaderUrls.add(url);
                        }
                    }
                }
                
                // Generate report
                StringBuilder report = new StringBuilder();
                report.append("CSRF Testing Report\n");
                report.append("=================\n\n");
                
                report.append("Tested URLs where CSRF token was present:\n");
                report.append("----------------------------------------\n\n");
                
                report.append("URLs with CSRF in Cookie only:\n");
                cookieUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("URLs with CSRF in Header only:\n");
                headerUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("URLs with CSRF in both Cookie and Header:\n");
                bothUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("Successfully Bypassed URLs:\n");
                report.append("-------------------------\n\n");
                
                report.append("Cookie-based CSRF bypassed:\n");
                bypassedCookieUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("Header-based CSRF bypassed:\n");
                bypassedHeaderUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("Failed Bypass Attempts:\n");
                report.append("----------------------\n\n");
                
                report.append("Cookie-based CSRF not bypassed:\n");
                failedCookieUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("Header-based CSRF not bypassed:\n");
                failedHeaderUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                report.append("\n");
                
                report.append("Both Cookie and Header CSRF not bypassed:\n");
                failedBothUrls.forEach(url -> report.append("- ").append(url).append("\n"));
                
                // Write to file
                Files.write(file.toPath(), report.toString().getBytes());
                
                // Show success message
                JOptionPane.showMessageDialog(mainPanel, 
                    "CSRF report exported successfully to:\n" + file.getAbsolutePath(),
                    "Export Success",
                    JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            callbacks.printError("Error exporting CSRF report: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                "Error exporting CSRF report: " + e.getMessage(),
                "Export Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
}