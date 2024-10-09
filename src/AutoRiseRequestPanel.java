

import java.awt.BorderLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;

import burp.ITextEditor;

public class AutoRiseRequestPanel {
  public static JPanel createRequestPanel(ITextEditor requestViewer, ITextEditor modifiedRequestViewer) {
    JPanel requestPanel = new JPanel(new BorderLayout());
    JTabbedPane tabbedPane = new JTabbedPane();

    JPanel originalRequestPanel = new JPanel(new BorderLayout());
    originalRequestPanel.add(new JLabel("Original Request"), BorderLayout.NORTH);
    originalRequestPanel.add(new JScrollPane(requestViewer.getComponent()), BorderLayout.CENTER);

    JPanel modifiedRequestPanel = new JPanel(new BorderLayout());
    modifiedRequestPanel.add(new JLabel("Modified Request"), BorderLayout.NORTH);
    modifiedRequestPanel.add(new JScrollPane(modifiedRequestViewer.getComponent()), BorderLayout.CENTER);

    tabbedPane.addTab("Original", originalRequestPanel);
    tabbedPane.addTab("Modified", modifiedRequestPanel);

    requestPanel.add(tabbedPane, BorderLayout.CENTER);
    return requestPanel;
}
}