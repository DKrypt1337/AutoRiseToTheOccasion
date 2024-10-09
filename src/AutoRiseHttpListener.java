import java.net.URL;

import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

public class AutoRiseHttpListener implements IHttpListener {
    private final AutoRiseToTheOccasion extension;

    public AutoRiseHttpListener(AutoRiseToTheOccasion extension) {
        this.extension = extension;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = extension.helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();

        if (messageIsRequest) {
            // Process request
            extension.requestMap.put(url, messageInfo);
            for (int i = 0; i < 10; i++) {
                if (extension.monitorCheckBoxes[i].isSelected()) {
                    extension.requestLists[i].addElement(url);
                }
            }
        } else {
            // Process response
            IHttpRequestResponse storedMessageInfo = extension.requestMap.get(url);
            if (storedMessageInfo != null) {
                // Create a new IHttpRequestResponse object that includes the response
                IHttpRequestResponse updatedMessageInfo = new IHttpRequestResponse() {
                    @Override
                    public byte[] getRequest() {
                        return storedMessageInfo.getRequest();
                    }

                    @Override
                    public void setRequest(byte[] message) {
                        storedMessageInfo.setRequest(message);
                    }

                    @Override
                    public byte[] getResponse() {
                        return messageInfo.getResponse();
                    }

                    @Override
                    public void setResponse(byte[] message) {
                        storedMessageInfo.setResponse(message);
                    }

                    @Override
                    public String getComment() {
                        return storedMessageInfo.getComment();
                    }

                    @Override
                    public void setComment(String comment) {
                        storedMessageInfo.setComment(comment);
                    }

                    @Override
                    public String getHighlight() {
                        return storedMessageInfo.getHighlight();
                    }

                    @Override
                    public void setHighlight(String color) {
                        storedMessageInfo.setHighlight(color);
                    }

                    @Override
                    public IHttpService getHttpService() {
                        return storedMessageInfo.getHttpService();
                    }

                    @Override
                    public void setHttpService(IHttpService httpService) {
                        storedMessageInfo.setHttpService(httpService);
                    }

                    @Override
                    public URL getUrl() {
                        return requestInfo.getUrl();
                    }

                    @Override
                    public int getPort() {
                        return storedMessageInfo.getHttpService().getPort();
                    }

                    @Override
                    public void setPort(int port) {
                        IHttpService service = storedMessageInfo.getHttpService();
                        IHttpService newService = extension.helpers.buildHttpService(service.getHost(), port, service.getProtocol());
                        storedMessageInfo.setHttpService(newService);
                    }

                    @Override
                    public String getProtocol() {
                        return storedMessageInfo.getHttpService().getProtocol();
                    }

                    @Override
                    public void setProtocol(String protocol) {
                        IHttpService service = storedMessageInfo.getHttpService();
                        IHttpService newService = extension.helpers.buildHttpService(service.getHost(), service.getPort(), protocol);
                        storedMessageInfo.setHttpService(newService);
                    }

                    @Override
                    public String getHost() {
                        return storedMessageInfo.getHttpService().getHost();
                    }

                    @Override
                    public void setHost(String host) {
                        IHttpService service = storedMessageInfo.getHttpService();
                        IHttpService newService = extension.helpers.buildHttpService(host, service.getPort(), service.getProtocol());
                        storedMessageInfo.setHttpService(newService);
                    }

                    @Override
                    public short getStatusCode() {
                        return messageInfo.getStatusCode();
                    }
                };
                extension.requestMap.put(url, updatedMessageInfo);
            }
        }
    }
}