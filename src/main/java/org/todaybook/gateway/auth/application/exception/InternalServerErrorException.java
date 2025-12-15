package org.todaybook.gateway.auth.application.exception;

import org.todaybook.gateway.error.GatewayErrorCode;
import org.todaybook.gateway.error.ServiceException;

public class InternalServerErrorException extends ServiceException {

  public InternalServerErrorException(String message) {
    super(GatewayErrorCode.INTERNAL_ERROR, message);
  }

  public InternalServerErrorException(String message, Throwable cause) {
    super(GatewayErrorCode.INTERNAL_ERROR, message, cause);
  }
}
