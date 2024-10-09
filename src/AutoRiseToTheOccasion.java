import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.HashMap;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;
import burp.ITextEditor;

public class AutoRiseToTheOccasion implements IBurpExtender, ITab {
    public JTextField[] roleTextFields;
    public JTextField[] authorizationTextFields;
    public JCheckBox[] roleCheckBoxes;
    public JCheckBox[] authorizationCheckBoxes;
    public JCheckBox[] monitorCheckBoxes;
    public ITextEditor[] requestViewers;
    public ITextEditor[] modifiedRequestViewers;
    public ITextEditor[] responseViewers;
    public ITextEditor[] modifiedResponseViewers;
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public DefaultTableModel[] tableModels;
    public JTable[] tables;
    public JScrollPane[] requestScrollPanes;
    public JPanel[] requestPanels;
    public Map<String, IHttpRequestResponse> requestMap;
    public JPanel mainPanel;
    public JTabbedPane tabbedPane;
    public DefaultListModel[] requestLists;
    public JList[] requestJLists;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.mainPanel = new JPanel(new BorderLayout());
        this.tabbedPane = new JTabbedPane();
        this.requestMap = new HashMap<>();

        // Create UI components
        this.requestScrollPanes = new JScrollPane[10];
        this.requestPanels = new JPanel[10];
        this.roleTextFields = new JTextField[10];
        this.roleCheckBoxes = new JCheckBox[10];
        this.requestViewers = new ITextEditor[10];
        this.modifiedRequestViewers = new ITextEditor[10];
        this.responseViewers = new ITextEditor[10];
        this.modifiedResponseViewers = new ITextEditor[10];
        this.authorizationTextFields = new JTextField[10];
        this.authorizationCheckBoxes = new JCheckBox[10];
        this.monitorCheckBoxes = new JCheckBox[10];

        // Create table models and tables
        this.tableModels = new DefaultTableModel[10];
        this.tables = new JTable[10];

        for (int i = 0; i < 10; i++) {
            // Create table model
            this.tableModels[i] = new DefaultTableModel();
            this.tableModels[i].addColumn("ID");
            this.tableModels[i].addColumn("HTTP Method");
            this.tableModels[i].addColumn("Full URL");
            this.tableModels[i].addColumn("Auth Status");
            this.tableModels[i].addColumn("HTTP Return Code");

            // Create table
            this.tables[i] = new JTable(this.tableModels[i]);
            this.tables[i].addMouseListener(new AutoRiseTableMouseListener(i, this));

            // Create scroll pane for table
            this.requestScrollPanes[i] = new JScrollPane(this.tables[i]);
            this.requestScrollPanes[i].setPreferredSize(new Dimension(300, 600));

            this.requestViewers[i] = callbacks.createTextEditor();
            this.modifiedRequestViewers[i] = callbacks.createTextEditor();
            this.responseViewers[i] = callbacks.createTextEditor();
            this.modifiedResponseViewers[i] = callbacks.createTextEditor();

            this.requestPanels[i] = new JPanel(new BorderLayout());

            // Create nested tabbed panes for original and modified requests
            JTabbedPane originalTabbedPane = new JTabbedPane();
            originalTabbedPane.addTab("Request", new JScrollPane(this.requestViewers[i].getComponent()));
            originalTabbedPane.addTab("Response", new JScrollPane(this.responseViewers[i].getComponent()));

            JTabbedPane modifiedTabbedPane = new JTabbedPane();
            modifiedTabbedPane.addTab("Request", new JScrollPane(this.modifiedRequestViewers[i].getComponent()));
            modifiedTabbedPane.addTab("Response", new JScrollPane(this.modifiedResponseViewers[i].getComponent()));

            JTabbedPane requestTabbedPane = new JTabbedPane();
            requestTabbedPane.addTab("Original Request", originalTabbedPane);
            requestTabbedPane.addTab("Modified Request", modifiedTabbedPane);
            
            JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPane.setTopComponent(this.requestScrollPanes[i]); // Request list on top
            splitPane.setBottomComponent(requestTabbedPane); // Request/Response tabs at the bottom
            splitPane.setDividerLocation(300); // Adjust as needed
            this.requestPanels[i].add(splitPane, BorderLayout.CENTER);

            this.roleTextFields[i] = new JTextField(40);
            this.authorizationTextFields[i] = new JTextField(40);
            this.roleCheckBoxes[i] = new JCheckBox("Enable Cookies");
            this.authorizationCheckBoxes[i] = new JCheckBox("Enable Authorization Header");

            JPanel rolePanel = new JPanel(new GridLayout(2, 1));

            // Cookie Panel
            JPanel cookiePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            cookiePanel.add(new JLabel("Cookies:"));
            this.roleTextFields[i].setPreferredSize(new Dimension(400, 30));
            cookiePanel.add(this.roleTextFields[i]);
            rolePanel.add(cookiePanel);

            // Authorization Header Panel
            JPanel authPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            authPanel.add(new JLabel("Authorization Header:"));
            this.authorizationTextFields[i].setPreferredSize(new Dimension(400, 30));
            authPanel.add(this.authorizationTextFields[i]);
            rolePanel.add(authPanel);

            JPanel checkBoxPanel = new JPanel();
            checkBoxPanel.setLayout(new GridLayout(3, 1));
            this.monitorCheckBoxes[i] = new JCheckBox("Enable Monitoring");
            checkBoxPanel.add(this.monitorCheckBoxes[i]);
            checkBoxPanel.add(this.roleCheckBoxes[i]);
            checkBoxPanel.add(this.authorizationCheckBoxes[i]);

            JPanel topPanel = new JPanel();
            topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS)); // Use BoxLayout for vertical stacking
            topPanel.add(rolePanel);
            topPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Add vertical space
            topPanel.add(checkBoxPanel);

            this.requestPanels[i].add(topPanel, BorderLayout.NORTH);

            this.tabbedPane.addTab("User " + (i + 1), this.requestPanels[i]);
        }

        // Add unauthenticated tab
        JPanel unauthenticatedPanel = new JPanel(new BorderLayout());
        unauthenticatedPanel.add(new JLabel("Unauthenticated"), BorderLayout.NORTH);
        JCheckBox enableCheckBox = new JCheckBox("Enable");
        unauthenticatedPanel.add(enableCheckBox, BorderLayout.CENTER);
        JTabbedPane unauthenticatedTabs = new JTabbedPane();
        unauthenticatedTabs.addTab("Request", new JScrollPane(new JTextArea()));
        unauthenticatedTabs.addTab("Response", new JScrollPane(new JTextArea()));
        unauthenticatedPanel.add(unauthenticatedTabs, BorderLayout.SOUTH);
        this.tabbedPane.addTab("Unauthenticated", unauthenticatedPanel);

        // Add tabs to main panel
        this.mainPanel.add(this.tabbedPane, BorderLayout.CENTER);

        // Register HTTP listener
        callbacks.setExtensionName("AutoRiseToTheOccasion");
        callbacks.registerHttpListener(new AutoRiseHttpListener(this, this.tableModels));

        // Add custom tab to Burp Suite
        callbacks.addSuiteTab(this);
    }

    @Override
    public String getTabCaption() {
        return "AutoRiseToTheOccasion";
    }

    @Override
    public Component getUiComponent() {
        return this.mainPanel;
    }
}
