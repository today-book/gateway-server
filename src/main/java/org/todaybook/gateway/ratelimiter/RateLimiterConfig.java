package org.todaybook.gateway.ratelimiter;

import java.net.InetSocketAddress;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway Rate Limiter 설정.
 *
 * <p>Spring Cloud Gateway의 {@link KeyResolver}를 이용하여 요청별 Rate Limit Key를 결정한다.
 *
 * <p>기본 전략:
 *
 * <ol>
 *   <li>deviceId 쿠키가 있으면 deviceId 기준으로 제한
 *   <li>deviceId가 없으면 IP 기준으로 제한
 * </ol>
 *
 * <p>이를 통해 NAT 환경(IP 공유)에서도 정상 사용자가 불필요하게 차단되는 것을 방지한다.
 */
@Configuration
public class RateLimiterConfig {

  /**
   * 기본(default) RateLimit KeyResolver.
   *
   * <p>Gateway 전반에 공통으로 적용되는 기본 Rate Limit 식별자 생성 전략이다.
   *
   * <p>결정 기준:
   *
   * <ol>
   *   <li>deviceId 쿠키가 존재하면 deviceId 기준
   *   <li>deviceId가 없으면 클라이언트 IP 기준으로 fallback
   * </ol>
   *
   * <p>새로운 공개 엔드포인트가 추가되었을 때 별도의 KeyResolver를 지정하지 않아도 최소한의 Rate Limit 보호를 제공하기 위한 "안전망" 용도로 사용한다.
   */
  @Bean
  public KeyResolver defaultKeyResolver() {
    return this::resolveRateLimitKey;
  }

  /**
   * Search API용 RateLimit KeyResolver.
   *
   * <p>공개 API이므로 호출 빈도가 높을 수 있어 deviceId 우선 → IP fallback 전략을 사용한다.
   */
  @Bean
  public KeyResolver searchKeyResolver() {
    return this::resolveRateLimitKey;
  }

  /**
   * Auth API용 RateLimit KeyResolver.
   *
   * <p>인증/토큰 관련 엔드포인트는 공격 표적이 되기 쉬우므로 Search API와 동일한 Key 전략을 사용하되, 실제 제한 강도는 Route 설정(YAML)에서 더
   * 타이트하게 조절한다.
   */
  @Bean
  public KeyResolver authKeyResolver() {
    return this::resolveRateLimitKey;
  }

  /**
   * Rate Limit Key를 결정하는 핵심 로직.
   *
   * <p>결정 우선순위:
   *
   * <ol>
   *   <li>deviceId 쿠키 (브라우저/기기 단위 식별)
   *   <li>클라이언트 IP (fallback)
   * </ol>
   *
   * <p>Key에는 접두사를 붙여 Redis 상에서 어떤 기준(deviceId/ip)인지 명확히 구분한다.
   *
   * @param exchange 현재 요청 컨텍스트
   * @return rate limit key
   */
  private Mono<String> resolveRateLimitKey(ServerWebExchange exchange) {
    String deviceKey = resolveDeviceId(exchange);
    if (deviceKey != null) {
      return Mono.just("deviceId:" + deviceKey);
    }

    return Mono.just("ip:" + resolveClientIp(exchange));
  }

  /**
   * 요청에서 deviceId 쿠키를 추출한다.
   *
   * <p>deviceId는 보안 토큰이 아닌 Rate Limit 식별용 랜덤 식별자이다.
   *
   * <p>존재하지 않거나 비어 있으면 {@code null}을 반환한다.
   *
   * @param exchange 현재 요청
   * @return deviceId 값 또는 null
   */
  private String resolveDeviceId(ServerWebExchange exchange) {
    HttpCookie deviceId = exchange.getRequest().getCookies().getFirst("deviceId");
    if (deviceId != null && !deviceId.getValue().isBlank()) {
      return deviceId.getValue();
    }
    return null;
  }

  /**
   * 클라이언트 IP 주소를 추출한다.
   *
   * <p>우선순위:
   *
   * <ol>
   *   <li>{@code X-Forwarded-For} 헤더 (프록시/ALB 환경)
   *   <li>{@link ServerWebExchange#getRequest()#getRemoteAddress()}
   *   <li>"unknown" (최후의 fallback)
   * </ol>
   *
   * <p>"unknown"은 비정상 상황에서도 RateLimiter가 예외 없이 동작하도록 하기 위한 안전장치이다.
   *
   * @param exchange 현재 요청
   * @return 클라이언트 IP 또는 "unknown"
   */
  private String resolveClientIp(ServerWebExchange exchange) {
    HttpHeaders headers = exchange.getRequest().getHeaders();

    // 1. 프록시 / ALB 환경: 실제 클라이언트 IP
    String xff = headers.getFirst("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }

    // 2. 직접 연결된 경우
    InetSocketAddress addr = exchange.getRequest().getRemoteAddress();
    if (addr != null && addr.getAddress() != null) {
      return addr.getAddress().getHostAddress();
    }

    // 3. 최후의 fallback (IP를 알 수 없는 경우)
    return "unknown";
  }
}
