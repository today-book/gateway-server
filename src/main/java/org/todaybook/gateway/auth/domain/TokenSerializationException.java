package org.todaybook.gateway.auth.domain;

public class TokenSerializationException extends RuntimeException {

  public TokenSerializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
