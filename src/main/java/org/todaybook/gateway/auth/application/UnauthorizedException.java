package org.todaybook.gateway.auth.application;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UnauthorizedException extends ResponseStatusException {

  public UnauthorizedException() {
    super(HttpStatus.UNAUTHORIZED, "인증되지 않은 사용자입니다.");
  }

  public UnauthorizedException(String reason) {
    super(HttpStatus.UNAUTHORIZED, reason);
  }
}
