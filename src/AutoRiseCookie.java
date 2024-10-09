

import java.util.Date;

import burp.ICookie;

public class AutoRiseCookie implements ICookie {
  private final String name;
  private final String value;
  private final String domain;
  private final String path;
  private final long expiration;
  private final boolean secure;
  private final boolean httpOnly;

  public AutoRiseCookie(String name, String value, String domain, String path, long expiration) {
    this.name = name;
    this.value = value;
    this.domain = domain;
    this.path = path;
    this.expiration = expiration;
    this.secure = false; // or true, depending on your requirements
    this.httpOnly = false; // or true, depending on your requirements
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public String getValue() {
    return value;
  }

  @Override
  public String getDomain() {
    return domain;
  }

  @Override
  public String getPath() {
    return path;
  }

  @Override
  public Date getExpiration() {
    return new Date(expiration);
  }

  public boolean isSecure() {
    return secure;
  }

  public boolean isHttpOnly() {
    return httpOnly;
  }
}