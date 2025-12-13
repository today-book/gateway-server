package org.todaybook.gateway.error;

/**
 * Gateway 내부에서 사용하는 기술적 예외.
 *
 * @author 김지원
 * @since 1.0.0.
 */
public class GatewayException extends RuntimeException {

  private final GatewayErrorCode errorCode;

  public GatewayException(GatewayErrorCode errorCode) {
    this.errorCode = errorCode;
  }

  public GatewayErrorCode getErrorCode() {
    return errorCode;
  }
}
