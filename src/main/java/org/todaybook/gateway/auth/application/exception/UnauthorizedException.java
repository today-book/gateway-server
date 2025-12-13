package org.todaybook.gateway.auth.application.exception;

import org.todaybook.gateway.error.GatewayErrorCode;
import org.todaybook.gateway.error.GatewayException;

/**
 * 인증되지 않은 요청을 표현하는 Gateway 전용 예외입니다.
 *
 * <p>Gateway에서는 HTTP 상태나 JSON 응답을 직접 결정하지 않고, {@link GatewayException}을 통해 전역 에러 핸들러로 위임합니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
public class UnauthorizedException extends GatewayException {

  /** 기본 인증 실패 예외를 생성합니다. */
  public UnauthorizedException(String message) {
    super(GatewayErrorCode.UNAUTHORIZED, message);
  }
}
