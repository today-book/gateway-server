package org.todaybook.gateway.security.device;

import java.time.Duration;
import java.util.UUID;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
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
    var request = exchange.getRequest();

    // 1) OPTIONS (CORS preflight)
    if (request.getMethod() == HttpMethod.OPTIONS) {
      return chain.filter(exchange);
    }

    // 2) auth 계열 요청 (login/refresh)
    String path = request.getURI().getPath();
    if (path.startsWith("/auth/")) {
      return chain.filter(exchange);
    }

    // 3) 이미 있으면 통과
    var existing = request.getCookies().getFirst(COOKIE_NAME);
    if (existing != null && !existing.getValue().isBlank()) {
      return chain.filter(exchange);
    }

    // 4) 최초 1회만 발급
    ResponseCookie cookie =
        ResponseCookie.from(COOKIE_NAME, UUID.randomUUID().toString())
            .path("/")
            .maxAge(Duration.ofDays(365))
            .sameSite("Lax")
            .httpOnly(true)
            .secure(true)
            .build();

    exchange.getResponse().addCookie(cookie);
    return chain.filter(exchange);
  }
}
