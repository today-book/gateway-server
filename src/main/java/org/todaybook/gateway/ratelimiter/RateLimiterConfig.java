package org.todaybook.gateway.ratelimiter;

import java.net.InetSocketAddress;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway Rate Limiter 설정.
 *
 * <p>Spring Cloud Gateway의 {@link KeyResolver}를 이용해 요청을 식별할 Rate Limit Key 생성 전략을 정의한다.
 *
 * <p>이 설정은 Gateway 전반에 공통으로 사용되는 <b>대표(Primary) 식별 전략</b>을 제공한다.
 *
 * <p>식별 전략:
 *
 * <ol>
 *   <li>{@code deviceId} 쿠키가 존재하면 device 단위로 제한
 *   <li>{@code deviceId}가 없으면 클라이언트 IP 기준으로 fallback
 * </ol>
 *
 * <p>이를 통해 NAT 환경(IP 공유)에서도 정상 사용자가 과도하게 차단되는 것을 방지한다.
 *
 * <p>특정 라우트에서 다른 식별 전략이 필요한 경우, 별도의 {@link KeyResolver}를 추가하고 라우트 설정에서 명시적으로 지정할 수 있다.
 */
@Configuration
public class RateLimiterConfig {

  /**
   * Gateway 공통 RateLimit KeyResolver.
   *
   * <p>GatewayAutoConfiguration에서 기본으로 사용되는 <b>대표 KeyResolver</b>로 등록된다.
   *
   * <p>결정 기준:
   *
   * <ol>
   *   <li>{@code deviceId} 쿠키가 있으면 device 단위 식별
   *   <li>쿠키가 없으면 클라이언트 IP 기준으로 fallback
   * </ol>
   *
   * <p>{@link Primary}로 지정되어 있어, 별도의 KeyResolver가 추가되더라도 Gateway 초기화 시 기본 식별 전략으로 사용된다.
   *
   * <p>Rate Limit 강도(replenishRate, burstCapacity)는 라우트 설정(YAML)에서 엔드포인트 특성에 맞게 조절한다.
   */
  @Bean
  @Primary
  public KeyResolver rateLimitKeyResolver() {
    return this::resolveRateLimitKey; // deviceId -> ip
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
