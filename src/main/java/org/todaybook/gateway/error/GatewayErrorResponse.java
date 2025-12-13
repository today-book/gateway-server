package org.todaybook.gateway.error;

/**
 * Gateway 공통 에러 응답.
 *
 * <p>common-core ErrorResponse와 "형태만" 맞춘다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
public record GatewayErrorResponse<T>(String code, T details) {

  public static GatewayErrorResponse<Void> of(String code) {
    return new GatewayErrorResponse<>(code, null);
  }

  public static <T> GatewayErrorResponse<T> of(String code, T details) {
    return new GatewayErrorResponse<>(code, details);
  }
}
