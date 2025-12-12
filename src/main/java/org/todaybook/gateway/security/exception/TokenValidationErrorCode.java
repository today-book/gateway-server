package org.todaybook.gateway.security.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.todaybook.commoncore.error.ErrorCode;

@RequiredArgsConstructor
public enum TokenValidationErrorCode implements ErrorCode {
  EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED.value()),
  INVALID_TOKEN_SIGNATURE(HttpStatus.UNAUTHORIZED.value()),
  INVALID_TOKEN_FORMAT(HttpStatus.BAD_REQUEST.value()),
  EMPTY_TOKEN(HttpStatus.BAD_REQUEST.value());

  private final int status;

  @Override
  public int getStatus() {
    return status;
  }

  @Override
  public String getCode() {
    return this.name();
  }
}
