

import java.net.URL;

import burp.IHttpService;

public interface AutoRiseIHttpRequestResponse {
    byte[] getRequest();
    void setRequest(byte[] message);
    byte[] getResponse();
    void setResponse(byte[] message);
    String getComment();
    void setComment(String comment);
    String getHighlight();
    void setHighlight(String color);
    IHttpService getHttpService();
    void setHttpService(IHttpService httpService);

    // Additional methods based on your error messages
    URL getUrl();
    int getPort();
    void setPort(int port);
    String getProtocol();
    void setProtocol(String protocol);
    String getHost();
    void setHost(String host);
}