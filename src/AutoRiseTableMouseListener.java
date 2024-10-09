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
        int row = extension.tables[userListIndex].getSelectedRow();
        if (row != -1) {
            // Get the selected row data
            String url = (String) extension.tableModels[userListIndex].getValueAt(row, 2);
            IHttpRequestResponse requestResponse = extension.requestMap.get(url);
            if (requestResponse != null) {
                // Update the request and response viewers
                extension.requestViewers[userListIndex].setText(requestResponse.getRequest());
                extension.responseViewers[userListIndex].setText(requestResponse.getResponse());
            }
        }
    }
}