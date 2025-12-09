package org.todaybook.gateway.security.jwt;

import io.jsonwebtoken.Claims;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.todaybook.gateway.security.PublicApiMatcher;
import reactor.core.publisher.Mono;

/**
 * JWT를 검증하고, 토큰에 포함된 Claims 정보를 내부 서비스 전달용 HTTP 헤더로 변환하여 주입하는 Gateway 전역 인증 필터입니다.
 *
 * <p>이 필터는 Gateway 진입 지점에서 다음 책임을 수행합니다.
 *
 * <ul>
 *   <li>Authorization 헤더에서 Bearer JWT 추출
 *   <li>JWT 유효성 검증
 *   <li>사용자 Claims → 내부 서비스용 헤더 변환
 *   <li>외부 Authorization 헤더 제거
 * </ul>
 *
 * <p>내부 서비스는 JWT를 직접 검증하지 않으며, {@code X-Gateway-Trusted} 헤더를 기준으로 Gateway를 신뢰하도록 구성됩니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  /** Gateway를 통과한 요청임을 내부 서비스에 알리기 위한 헤더. */
  private static final String HEADER_GATEWAY_TRUSTED = "X-Gateway-Trusted";

  /** 요청 클라이언트 타입(USER / PUBLIC 등)을 구분하기 위한 헤더. */
  private static final String HEADER_CLIENT_TYPE = "X-Client-Type";

  /** Authorization 헤더의 Bearer 접두사. */
  private static final String AUTHORIZATION_PREFIX = "Bearer ";

  /** 내부 서비스 전달용 사용자 ID 헤더. */
  private static final String HEADER_USER_ID = "X-User-Id";

  /** 내부 서비스 전달용 사용자 닉네임 헤더. */
  private static final String HEADER_USER_NICKNAME = "X-User-Nickname";

  /** 내부 서비스 전달용 사용자 권한 헤더. */
  private static final String HEADER_USER_ROLES = "X-User-Roles";

  private final JwtProvider jwtProvider;
  private final PublicApiMatcher publicApiMatcher;

  /**
   * Gateway 전역 필터 중 가장 먼저 실행되도록 설정합니다.
   *
   * <p>JWT 인증은 다른 필터보다 선행되어야 하므로 {@code HIGHEST_PRECEDENCE}를 사용합니다.
   *
   * @return 필터 우선순위 값
   */
  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  /**
   * 요청의 JWT를 검증하고, 인증 정보가 있는 경우 내부 서비스 전달용 헤더를 주입합니다.
   *
   * <p>처리 흐름은 다음과 같습니다.
   *
   * <ol>
   *   <li>Public API 여부 판단
   *   <li>Authorization 헤더에서 JWT 추출
   *   <li>JWT 미존재 + Public API → PUBLIC 헤더 주입 후 통과
   *   <li>JWT 유효성 검증 실패 → 401 응답
   *   <li>JWT Claims → 내부 전용 헤더로 변환
   * </ol>
   *
   * @param exchange 현재 요청/응답 컨텍스트
   * @param chain Gateway 필터 체인
   * @return 필터 체인 실행 결과
   */
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    boolean isPublicApi = publicApiMatcher.isPublic(exchange.getRequest());

    String token = extractToken(exchange);
    if (token == null) {
      if (isPublicApi) {
        return chain.filter(setPublicHeaders(exchange));
      }
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
   * Public API 요청에 대해 Gateway 신뢰 헤더를 설정합니다.
   *
   * <p>인증 정보는 없지만, 내부 서비스가 Gateway 통과 여부를 판단할 수 있도록 {@code X-Gateway-Trusted=true}, {@code
   * X-Client-Type=PUBLIC}을 주입합니다.
   *
   * @param exchange 요청 컨텍스트
   * @return 헤더가 추가된 ServerWebExchange
   */
  private ServerWebExchange setPublicHeaders(ServerWebExchange exchange) {
    return exchange
        .mutate()
        .request(
            builder ->
                builder.header(HEADER_GATEWAY_TRUSTED, "true").header(HEADER_CLIENT_TYPE, "PUBLIC"))
        .build();
  }

  /**
   * Authorization 헤더에서 Bearer JWT 토큰을 추출합니다.
   *
   * @param exchange 요청 컨텍스트
   * @return JWT 토큰 문자열, 존재하지 않으면 null
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
   * <p>JWT 위변조, 만료 등 인증이 실패한 경우 즉시 응답을 종료합니다.
   *
   * @param exchange 요청 컨텍스트
   * @return 응답 완료 신호
   */
  private Mono<Void> unauthorized(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }

  /**
   * JWT Claims 정보를 내부 서비스용 HTTP 헤더로 변환하여 요청에 주입합니다.
   *
   * <p>다음 작업을 수행합니다.
   *
   * <ul>
   *   <li>외부 Authorization 헤더 제거
   *   <li>Gateway 신뢰 헤더 설정
   *   <li>사용자 식별 정보 헤더 주입
   * </ul>
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
                    .header(HEADER_GATEWAY_TRUSTED, "true")
                    .header(HEADER_CLIENT_TYPE, "USER")
                    .header(HEADER_USER_ID, claims.getSubject())
                    .header(HEADER_USER_NICKNAME, encodeHeaderValue(extractUserNickname(claims)))
                    .header(HEADER_USER_ROLES, String.join(",", extractUserRoles(claims))))
        .build();
  }

  /**
   * JWT Claims에서 사용자 닉네임을 추출합니다.
   *
   * @param claims JWT Claims
   * @return 닉네임, 존재하지 않으면 "Unknown"
   */
  private String extractUserNickname(Claims claims) {
    Object value = claims.get("nickname");
    return value != null ? value.toString() : "Unknown";
  }

  /**
   * JWT Claims에서 사용자 권한 목록을 추출합니다.
   *
   * <p>권한 정보가 없거나 형식이 맞지 않는 경우 빈 리스트를 반환합니다.
   *
   * @param claims JWT Claims
   * @return 사용자 권한 문자열 목록
   */
  private List<String> extractUserRoles(Claims claims) {
    Object roles = claims.get("roles");

    if (roles == null) {
      return List.of();
    }

    if (roles instanceof List<?> list) {
      return list.stream().map(String::valueOf).toList();
    }

    return List.of();
  }

  /**
   * HTTP 헤더로 전달 가능하도록 값을 UTF-8 기준으로 URL 인코딩합니다.
   *
   * <p>닉네임 등 한글이 포함된 값이 헤더에서 깨지는 것을 방지하기 위함입니다.
   *
   * @param value 원본 문자열
   * @return URL 인코딩된 문자열
   */
  private String encodeHeaderValue(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
