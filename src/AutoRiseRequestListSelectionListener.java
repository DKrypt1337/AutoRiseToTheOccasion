import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

public class AutoRiseRequestListSelectionListener implements ListSelectionListener {
    private final int userListIndex;
    private final AutoRiseToTheOccasion extension;
    private final Map<String, Long> processedUrls;
    private static final long DEBOUNCE_INTERVAL = 1000; // 1 second

    public AutoRiseRequestListSelectionListener(int userListIndex, AutoRiseToTheOccasion extension) {
        this.userListIndex = userListIndex;
        this.extension = extension;
        this.processedUrls = new HashMap<>();
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        if (!e.getValueIsAdjusting()) {
            String url = (String) extension.getRequestJLists()[userListIndex].getSelectedValue();
            if (url != null) {
                log("Selected URL: " + url);
                IHttpRequestResponse originalRequestResponse = extension.getRequestMap().get(url);
                IRequestInfo requestInfo = extension.getHelpers().analyzeRequest(originalRequestResponse);

                // Log original request and response for debugging
                logRequestResponse("Original", originalRequestResponse);

                // Update the original request and response viewers
                log("Updating original request and response viewers.");
                extension.getRequestViewers()[userListIndex].setText(originalRequestResponse.getRequest());
                extension.getResponseViewers()[userListIndex].setText(originalRequestResponse.getResponse());

                final byte[][] modifiedRequestHolder = {originalRequestResponse.getRequest().clone()};
                final byte[][] modifiedResponseHolder = {originalRequestResponse.getResponse().clone()};

                boolean isModified = false;

                if (extension.getRoleCheckBoxes()[userListIndex].isSelected() && !extension.getRoleTextFields()[userListIndex].getText().isEmpty()) {
                    isModified = true;
                    log("Modifying request with cookies...");
                    // Modify request with cookies
                    List<ICookie> modifiedCookies = new ArrayList<>();
                    String[] cookieArray = extension.getRoleTextFields()[userListIndex].getText().split(";");
                    for (String cookie : cookieArray) {
                        String[] cookieNameValuePair = cookie.split("=");
                        if (cookieNameValuePair.length == 2) {
                            modifiedCookies.add(new AutoRiseCookie(cookieNameValuePair[0].trim(), cookieNameValuePair[1].trim(), "", "", System.currentTimeMillis()));
                        }
                    }
                    List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                    for (int i = 0; i < headers.size(); i++) {
                        String header = headers.get(i);
                        if (header.startsWith("Cookie:")) {
                            String[] cookiePairs = header.substring(7).split("; ");
                            for (int j = 0; j < cookiePairs.length; j++) {
                                String[] cookieNameValuePair = cookiePairs[j].split("=");
                                if (cookieNameValuePair.length == 2) {
                                    for (ICookie cookie : modifiedCookies) {
                                        if (cookie.getName().equals(cookieNameValuePair[0].trim())) {
                                            cookiePairs[j] = cookie.getName() + "=" + cookie.getValue();
                                        }
                                    }
                                }
                            }
                            headers.set(i, "Cookie: " + String.join("; ", cookiePairs));
                        }
                    }
                    // Extract body from original request
                    int bodyOffset = requestInfo.getBodyOffset();
                    byte[] body = new byte[modifiedRequestHolder[0].length - bodyOffset];
                    System.arraycopy(modifiedRequestHolder[0], bodyOffset, body, 0, body.length);

                    modifiedRequestHolder[0] = extension.getHelpers().buildHttpMessage(headers, body);
                    log("Modified request prepared.");
                }

                if (isModified) {
                    log("Setting modified request and response.");
                    // Log modified request and response for debugging
                    logRequestResponse("Modified", new IHttpRequestResponse() {
                        public byte[] getRequest() { return modifiedRequestHolder[0]; }
                        public void setRequest(byte[] message) {}
                        public byte[] getResponse() { return modifiedResponseHolder[0]; }
                        public void setResponse(byte[] message) {}
                        public String getComment() { return null; }
                        public void setComment(String comment) {}
                        public String getHighlight() { return null; }
                        public void setHighlight(String color) {}
                        public IHttpService getHttpService() { return originalRequestResponse.getHttpService(); }
                        public void setHttpService(IHttpService httpService) {}
                        public String getHost() { return originalRequestResponse.getHttpService().getHost(); }
                        public int getPort() { return originalRequestResponse.getHttpService().getPort(); }
                        public String getProtocol() { return originalRequestResponse.getHttpService().getProtocol(); }
                        public short getStatusCode() { return originalRequestResponse.getStatusCode(); }
                        public URL getUrl() { return originalRequestResponse.getUrl(); }
                        public void setHost(String host) { /* Not applicable */ }
                        public void setPort(int port) { /* Not applicable */ }
                        public void setProtocol(String protocol) { /* Not applicable */ }
                    });

                    // Set modified request and response
                    extension.getModifiedRequestViewers()[userListIndex].setText(modifiedRequestHolder[0]);
                    extension.getModifiedResponseViewers()[userListIndex].setText(modifiedResponseHolder[0]);
                } else {
                    // Display a message if no modifications are enabled
                    extension.getModifiedRequestViewers()[userListIndex].setText("Enable cookies or authorization to see modified requests.".getBytes());
                    extension.getModifiedResponseViewers()[userListIndex].setText("Enable cookies or authorization to see modified responses.".getBytes());
                }
            }
        }
    }

    private void logRequestResponse(String type, IHttpRequestResponse requestResponse) {
        log(type + " Request: " + new String(requestResponse.getRequest()));
        log(type + " Response: " + new String(requestResponse.getResponse()));
    }

    private void log(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        extension.getStdout().println("[" + timestamp + "] " + message);
    }
}