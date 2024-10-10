import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import burp.IHttpRequestResponse;

public class AutoRiseTableMouseListener extends MouseAdapter {
    private final int userListIndex;
    private final AutoRiseToTheOccasion extension;

    public AutoRiseTableMouseListener(int userListIndex, AutoRiseToTheOccasion extension) {
        this.userListIndex = userListIndex;
        this.extension = extension;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        // Handle the selection of rows
        int row = extension.getTables()[userListIndex].getSelectedRow();
        if (row != -1) {
            // Get the selected row data
            String url = (String) extension.getTableModels()[userListIndex].getValueAt(row, 2);
            IHttpRequestResponse requestResponse = extension.getRequestMap().get(url);
            if (requestResponse != null) {
                // Update the request and response viewers
                extension.getRequestViewers()[userListIndex].setText(requestResponse.getRequest());
                extension.getResponseViewers()[userListIndex].setText(requestResponse.getResponse());
            }
        }
    }
}