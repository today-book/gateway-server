package org.todaybook.gateway.security.exception;

public class TokenSerializationException extends RuntimeException {

  public TokenSerializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
