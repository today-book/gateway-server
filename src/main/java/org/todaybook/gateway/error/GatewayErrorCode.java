package org.todaybook.gateway.error;

/**
 * Gateway 레벨 에러 코드 정의.
 *
 * <p>Gateway는 인증/인가, 요청 유효성, 트래픽 제어, 라우팅 등 시스템의 경계(boundary) 역할만 수행하므로, 비즈니스 도메인 에러는 포함하지 않습니다.
 *
 * <p>각 에러 코드는 HTTP 상태 코드와 1:1 또는 의미적으로 매핑되며, 실제 응답 포맷(JSON)은 {@link
 * GatewayErrorWebExceptionHandler}에서 결정됩니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
public enum GatewayErrorCode {

  /**
   * 인증되지 않은 요청.
   *
   * <p>JWT가 없거나, 유효하지 않거나, 인증이 필요한 API에 접근한 경우 사용됩니다. 일반적으로 로그인 필요 상황을 의미합니다.
   */
  UNAUTHORIZED(401),

  /**
   * 인증은 되었으나 접근 권한이 없는 요청.
   *
   * <p>사용자의 권한(role, scope 등)이 해당 리소스 접근 조건을 만족하지 못한 경우입니다.
   */
  FORBIDDEN(403),

  /**
   * 요청 횟수 제한 초과.
   *
   * <p>Rate Limiter에 의해 차단된 경우 사용되며, 클라이언트는 일정 시간 후 재시도를 유도받습니다.
   */
  RATE_LIMIT_EXCEEDED(429),

  /**
   * 다운스트림 서비스 사용 불가.
   *
   * <p>대상 서비스가 내려가 있거나, 네트워크 연결 자체가 불가능한 경우입니다. 예: Connection Timeout, 서버 미기동 등.
   */
  SERVICE_UNAVAILABLE(503),

  /**
   * Gateway 내부 처리 중 알 수 없는 오류.
   *
   * <p>명시적으로 분류되지 않은 예외에 대해 사용하는 최종 fallback 에러입니다.
   */
  INTERNAL_ERROR(500),

  /**
   * 필수 요청 값 누락.
   *
   * <p>요청 처리에 필요한 값이 전달되지 않은 경우를 의미합니다. 다음과 같은 상황에서 발생할 수 있습니다.
   *
   * <ul>
   *   <li>필수 쿠키 누락 (예: Refresh Token Cookie)
   *   <li>필수 HTTP 헤더 누락
   *   <li>필수 쿼리 파라미터 누락
   *   <li>필수 경로 변수(Path Variable) 누락
   * </ul>
   */
  MISSING_REQUEST_VALUE(400),

  /**
   * 요청 바인딩 또는 파싱 실패.
   *
   * <p>RequestBody 바인딩 실패, 검증 오류, JSON 파싱 오류 등 요청 형식 자체가 올바르지 않은 경우를 포괄합니다.
   */
  REQUEST_BIND_ERROR(400),

  /**
   * 지원하지 않는 Content-Type.
   *
   * <p>예: application/json이 필요한 API에 다른 Content-Type으로 요청한 경우.
   */
  UNSUPPORTED_MEDIA_TYPE(415),

  /**
   * 허용되지 않은 HTTP Method.
   *
   * <p>예: POST 전용 API를 GET으로 호출한 경우.
   */
  METHOD_NOT_ALLOWED(405),

  /**
   * 존재하지 않는 경로 또는 라우팅 실패.
   *
   * <p>Gateway에 매핑되지 않은 경로로 요청이 들어온 경우입니다.
   */
  NOT_FOUND(404),

  /**
   * Gateway 타임아웃.
   *
   * <p>요청은 전달되었으나, 다운스트림 서비스로부터 제한 시간 내 응답을 받지 못한 경우입니다.
   */
  GATEWAY_TIMEOUT(504);

  /** HTTP 응답에 사용될 상태 코드. */
  private final int status;

  GatewayErrorCode(int status) {
    this.status = status;
  }

  /**
   * 에러 코드에 대응되는 HTTP 상태 코드를 반환합니다.
   *
   * @return HTTP 상태 코드
   */
  public int status() {
    return status;
  }
}
