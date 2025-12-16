package org.todaybook.gateway.security.device;

import java.time.Duration;
import java.util.UUID;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // 최대한 앞에서
public class DeviceIdCookieFilter implements WebFilter {

  private static final String COOKIE_NAME = "deviceId";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    var existing = exchange.getRequest().getCookies().getFirst(COOKIE_NAME);
    if (existing != null && !existing.getValue().isBlank()) {
      return chain.filter(exchange);
    }

    String deviceId = UUID.randomUUID().toString();

    ResponseCookie cookie =
        ResponseCookie.from(COOKIE_NAME, deviceId)
            .path("/")
            .maxAge(Duration.ofDays(365))
            .sameSite("Lax")
            .httpOnly(true) // JS에서 못 읽게(서버는 읽을 수 있음). rate limit 용도면 이게 더 안전
            .secure(true) // HTTPS면 true 권장 (local은 프로필로 false 처리)
            .build();

    exchange.getResponse().addCookie(cookie);
    return chain.filter(exchange);
  }
}
