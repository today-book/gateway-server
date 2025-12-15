package org.todaybook.gateway.error;

import lombok.Getter;

/**
 * Gateway 내부에서 사용하는 기술적 예외.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Getter
public class ServiceException extends RuntimeException {

  private final GatewayErrorCode errorCode;

  public ServiceException(GatewayErrorCode errorCode) {
    super(errorCode.name());
    this.errorCode = errorCode;
  }

  public ServiceException(GatewayErrorCode errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  public ServiceException(GatewayErrorCode errorCode, Throwable cause) {
    super(errorCode.name(), cause);
    this.errorCode = errorCode;
  }

  public ServiceException(GatewayErrorCode errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }
}
