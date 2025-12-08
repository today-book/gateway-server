package org.todaybook.gateway.security.jwt;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  private static final String AUTHORIZATION_PREFIX = "Bearer ";
  private static final String HEADER_USER_ID = "X-User-Id";
  private static final String HEADER_USER_NAME = "X-User-Name";

  private final JwtProvider jwtProvider;

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

    String token = extractToken(exchange);
    if (token == null) {
      return chain.filter(exchange);
    }

    if (!jwtProvider.validate(token)) {
      return unauthorized(exchange);
    }

    Claims claims = jwtProvider.getClaims(token);
    ServerWebExchange enrichedExchange = enrichExchangeWithClaims(exchange, claims);

    return chain.filter(enrichedExchange);
  }

  /** Authorization 헤더에서 JWT 토큰을 추출합니다. */
  private String extractToken(ServerWebExchange exchange) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith(AUTHORIZATION_PREFIX)) {
      return null;
    }
    return authHeader.substring(AUTHORIZATION_PREFIX.length());
  }

  /** 인증 실패(401) 응답 처리. */
  private Mono<Void> unauthorized(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }

  /** Claims 정보를 내부 서비스 전달용 헤더로 주입합니다. */
  private ServerWebExchange enrichExchangeWithClaims(ServerWebExchange exchange, Claims claims) {

    return exchange
        .mutate()
        .request(
            req ->
                req.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                    .header(HEADER_USER_ID, claims.getSubject())
                    .header(HEADER_USER_NAME, String.valueOf(claims.get("nickname"))))
        .build();
  }
}
