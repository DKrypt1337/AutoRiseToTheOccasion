

import java.util.ArrayList;
import java.util.Date;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.JTextComponent;

import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class AutoRiseRequestListSelectionListener implements ListSelectionListener {
    private final int userListIndex;
    private final AutoRiseToTheOccasion extension;

    public AutoRiseRequestListSelectionListener(int userListIndex, AutoRiseToTheOccasion extension) {
        this.userListIndex = userListIndex;
        this.extension = extension;
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        if (!e.getValueIsAdjusting()) {
            String url = (String) extension.requestJLists[userListIndex].getSelectedValue();
            if (url != null) {
                IHttpRequestResponse requestResponse = extension.requestMap.get(url);
                IRequestInfo requestInfo = extension.helpers.analyzeRequest(requestResponse);

                // Update the original request and response viewers
                extension.requestViewers[userListIndex].setText(requestResponse.getRequest());
                extension.responseViewers[userListIndex].setText(requestResponse.getResponse());

                byte[] modifiedRequest = requestResponse.getRequest();
                byte[] modifiedResponse = requestResponse.getResponse();

                boolean isModified = false;

                if (extension.roleCheckBoxes[userListIndex].isSelected() && !extension.roleTextFields[userListIndex].getText().isEmpty()) {
                    isModified = true;
                    // Modify request with cookies
                    java.util.List<ICookie> modifiedCookies = new ArrayList<>();
                    String[] cookieArray = extension.roleTextFields[userListIndex].getText().split(";");
                    for (String cookie : cookieArray) {
                        String[] cookieNameValuePair = cookie.split("=");
                        modifiedCookies.add(new AutoRiseCookie(cookieNameValuePair[0].trim(), cookieNameValuePair[1].trim(), "", "", new Date().getTime()));
                    }
                    java.util.List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                    for (String header : headers) {
                        if (header.startsWith("Cookie:")) {
                            headers.remove(header);
                            break;
                        }
                    }
                    for (ICookie cookie : modifiedCookies) {
                        headers.add("Cookie: " + cookie.getName() + "=" + cookie.getValue());
                    }
                    modifiedRequest = extension.helpers.buildHttpMessage(headers, requestResponse.getRequest());
                } else if (extension.roleCheckBoxes[userListIndex].isSelected() && extension.roleTextFields[userListIndex].getText().isEmpty()) {
                    // Display a message to the user to enter cookies
                    ((JTextComponent) extension.requestViewers[userListIndex].getComponent()).setText("Please enter cookies");
                } else if (extension.authorizationCheckBoxes[userListIndex].isSelected() && extension.authorizationTextFields[userListIndex].getText().isEmpty()) {
                    // Display a message to the user to enter authorization header
                    ((JTextComponent) extension.requestViewers[userListIndex].getComponent()).setText("Please enter authorization header");
                }

                if (extension.authorizationCheckBoxes[userListIndex].isSelected() && !extension.authorizationTextFields[userListIndex].getText().isEmpty()) {
                    isModified = true;
                    // Modify request with authorization header
                    java.util.List<String> headers = new ArrayList<>(extension.helpers.analyzeRequest(modifiedRequest).getHeaders());
                    for (String header : headers) {
                        if (header.startsWith("Authorization:")) {
                            headers.remove(header);
                            break;
                        }
                    }
                    headers.add("Authorization: " + extension.authorizationTextFields[userListIndex].getText());
                    modifiedRequest = extension.helpers.buildHttpMessage(headers, modifiedRequest);
                }

                if (isModified) {
                    // Set modified request and response
                    extension.modifiedRequestViewers[userListIndex].setText(modifiedRequest);
                    // Assume modifiedResponse is processed or fetched based on modifiedRequest
                    extension.modifiedResponseViewers[userListIndex].setText(modifiedResponse);
                } else {
                    // Display a message if no modifications are enabled
                    extension.modifiedRequestViewers[userListIndex].setText("Enable cookies or authorization to see modified requests.".getBytes());
                    extension.modifiedResponseViewers[userListIndex].setText("Enable cookies or authorization to see modified responses.".getBytes());
                }
            }
        }
    }

    public AutoRiseToTheOccasion getExtension() {
        return extension;
    }
}