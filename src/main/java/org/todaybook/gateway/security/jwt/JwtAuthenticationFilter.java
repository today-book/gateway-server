package org.todaybook.gateway.security.jwt;

import io.jsonwebtoken.Claims;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * JWT를 검증하고, 토큰에 포함된 Claims 정보를 내부 서비스 전달용 HTTP 헤더로 변환하여 주입하는 Gateway 전역 필터입니다.
 *
 * <p>외부 요청의 Authorization 헤더를 제거하고, 내부 서비스에서는 인증이 완료된 요청으로 처리할 수 있도록 사용자 식별 정보를 헤더로 전달합니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  /** Authorization 헤더의 Bearer 접두사. */
  private static final String AUTHORIZATION_PREFIX = "Bearer ";

  /** 내부 서비스 전달용 사용자 ID 헤더. */
  private static final String HEADER_USER_ID = "X-User-Id";

  /** 내부 서비스 전달용 사용자 닉네임 헤더. */
  private static final String HEADER_USER_NICKNAME = "X-User-Nickname";

  /** 내부 서비스 전달용 사용자 권한 헤더. */
  private static final String HEADER_USER_ROLES = "X-User-Roles";

  private final JwtProvider jwtProvider;

  /**
   * 필터 실행 순서를 최상위로 지정합니다.
   *
   * @return 필터 우선순위
   */
  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  /**
   * 요청에서 JWT를 추출·검증한 뒤, 유효한 경우 Claims 정보를 헤더에 주입하여 다음 필터로 전달합니다.
   *
   * @param exchange 현재 요청/응답 컨텍스트
   * @param chain 필터 체인
   * @return 필터 체인 실행 결과
   */
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

  /**
   * Authorization 헤더에서 Bearer 토큰을 추출합니다.
   *
   * @param exchange 요청 컨텍스트
   * @return JWT 토큰 문자열 또는 null
   */
  private String extractToken(ServerWebExchange exchange) {
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith(AUTHORIZATION_PREFIX)) {
      return null;
    }
    return authHeader.substring(AUTHORIZATION_PREFIX.length());
  }

  /**
   * 인증 실패 시 401 Unauthorized 응답을 반환합니다.
   *
   * @param exchange 요청 컨텍스트
   * @return 응답 완료 신호
   */
  private Mono<Void> unauthorized(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }

  /**
   * JWT Claims 정보를 내부 서비스에서 사용 가능한 헤더로 변환하여 주입합니다.
   *
   * <p>Authorization 헤더는 제거되며, 사용자 ID, 닉네임, 권한 정보가 새로운 헤더로 추가됩니다.
   *
   * @param exchange 요청 컨텍스트
   * @param claims JWT Claims
   * @return 헤더가 보강된 ServerWebExchange
   */
  private ServerWebExchange enrichExchangeWithClaims(ServerWebExchange exchange, Claims claims) {
    return exchange
        .mutate()
        .request(
            req ->
                req.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                    .header(HEADER_USER_ID, claims.getSubject())
                    .header(HEADER_USER_NICKNAME, encodeHeaderValue(extractUserNickname(claims)))
                    .header(HEADER_USER_ROLES, extractUserRoles()))
        .build();
  }

  /**
   * Claims 에서 사용자 닉네임을 추출합니다.
   *
   * @param claims JWT Claims
   * @return 닉네임 또는 기본값
   */
  private String extractUserNickname(Claims claims) {
    Object value = claims.get("nickname");
    return value != null ? value.toString() : "Unknown";
  }

  /**
   * 사용자 권한 정보를 추출합니다.
   *
   * <p>현재는 고정 값이며, 추후 Claims 기반으로 확장될 수 있습니다.
   *
   * @return 사용자 권한 문자열
   */
  private String extractUserRoles() {
    return "ROLE_USER";
  }

  /**
   * HTTP 헤더 안전성을 위해 값을 UTF-8 기준으로 URL 인코딩합니다.
   *
   * @param value 원본 값
   * @return 인코딩된 값
   */
  private String encodeHeaderValue(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
