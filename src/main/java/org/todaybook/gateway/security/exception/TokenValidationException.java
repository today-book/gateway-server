package org.todaybook.gateway.security.exception;

import org.todaybook.commoncore.error.AbstractServiceException;
import org.todaybook.commoncore.error.ErrorCode;

public class TokenValidationException extends AbstractServiceException {

  public TokenValidationException(ErrorCode errorCode, Object... errorArgs) {
    super(errorCode, errorArgs);
  }
}
