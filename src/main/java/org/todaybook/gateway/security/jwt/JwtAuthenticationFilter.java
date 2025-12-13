package org.todaybook.gateway.security.jwt;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.todaybook.gateway.error.GatewayErrorCode;
import org.todaybook.gateway.error.GatewayException;
import org.todaybook.gateway.security.publicapi.PublicApiMatcher;
import reactor.core.publisher.Mono;

/**
 * Gateway 전역 JWT 인증 후처리 필터.
 *
 * <p>이 필터는 Spring Security Resource Server에 의해 JWT 검증이 완료된 이후 실행되며, {@link JwtAuthenticationToken}에
 * 포함된 인증 정보를 내부 서비스 간 통신을 위한 HTTP 헤더로 변환하는 책임만 수행합니다.
 *
 * <p>JWT의 서명 검증, 만료 검증, 포맷 검증 등은 본 필터의 책임이 아니며, Spring Security가 생성한 인증 객체를 신뢰하는 구조입니다.
 *
 * <p>외부 클라이언트의 Authorization 헤더는 내부 서비스로 전달하지 않고, Gateway를 신뢰 지점(trust boundary)으로 삼아 내부 전용 헤더 기반
 * 인증을 수행하도록 설계되었습니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  /**
   * Gateway를 통해 인증/검증된 요청임을 내부 서비스에 알리기 위한 신뢰 헤더.
   *
   * <p>내부 서비스는 외부 Authorization 헤더가 아닌 이 헤더의 존재 여부를 기준으로 요청 신뢰 여부를 판단합니다.
   */
  private static final String HEADER_GATEWAY_TRUSTED = "X-Gateway-Trusted";

  /**
   * 요청 주체의 클라이언트 타입.
   *
   * <ul>
   *   <li>{@code USER} : JWT 인증이 완료된 사용자 요청
   *   <li>{@code PUBLIC} : 인증이 필요 없는 공개 API 요청
   * </ul>
   */
  private static final String HEADER_CLIENT_TYPE = "X-Client-Type";

  /** 내부 서비스 전달용 사용자 식별자 (JWT subject). */
  private static final String HEADER_USER_ID = "X-User-Id";

  /** 내부 서비스 전달용 사용자 닉네임 (URL 인코딩 처리됨). */
  private static final String HEADER_USER_NICKNAME = "X-User-Nickname";

  /** 내부 서비스 전달용 사용자 권한 목록 (comma-separated). */
  private static final String HEADER_USER_ROLES = "X-User-Roles";

  /** Public API 여부를 판단하기 위한 매처. */
  private final PublicApiMatcher publicApiMatcher;

  /**
   * Spring Security WebFilterChain 이후에 실행되도록 필터 순서를 지정합니다.
   *
   * <p>JWT 인증 결과(SecurityContext)가 이미 생성된 이후 해당 인증 정보를 후처리해야 하므로 {@link Ordered#LOWEST_PRECEDENCE}를
   * 사용합니다.
   */
  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE;
  }

  /**
   * Gateway 전역 인증 후처리 필터 로직.
   *
   * <p>처리 흐름은 다음과 같습니다.
   *
   * <ol>
   *   <li>SecurityContext에서 {@link JwtAuthenticationToken} 조회
   *   <li>인증된 JWT가 존재하면 내부 서비스용 헤더로 변환
   *   <li>JWT가 없고 Public API인 경우 Public 전용 헤더 설정
   *   <li>JWT가 없고 Private API인 경우 401 Unauthorized 응답
   * </ol>
   */
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    boolean isPublicApi = publicApiMatcher.isPublic(exchange.getRequest());

    Mono<ServerWebExchange> exchangeMono =
        exchange
            .getPrincipal()
            .cast(JwtAuthenticationToken.class)
            .map(AbstractOAuth2TokenAuthenticationToken::getToken)
            .map(jwt -> enrichExchangeWithJwt(exchange, jwt))
            .switchIfEmpty(
                isPublicApi
                    ? Mono.just(setPublicHeaders(exchange))
                    : Mono.error(new GatewayException(GatewayErrorCode.UNAUTHORIZED)));

    return exchangeMono.flatMap(chain::filter);
  }

  /**
   * Public API 요청에 대해 Gateway 신뢰 헤더를 설정합니다.
   *
   * <p>외부 Authorization 헤더는 제거되며, 내부 서비스는 {@code X-Gateway-Trusted=true} 헤더를 통해 Gateway를 거친 요청임을
   * 신뢰합니다.
   *
   * <p>사용자 식별 정보는 포함하지 않습니다.
   */
  private ServerWebExchange setPublicHeaders(ServerWebExchange exchange) {
    return exchange
        .mutate()
        .request(
            req ->
                req.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                    .header(HEADER_GATEWAY_TRUSTED, "true")
                    .header(HEADER_CLIENT_TYPE, "PUBLIC"))
        .build();
  }

  /**
   * 인증된 JWT 정보를 내부 서비스 통신을 위한 HTTP 헤더로 변환합니다.
   *
   * <p>처리 내용:
   *
   * <ul>
   *   <li>외부 Authorization 헤더 제거
   *   <li>Gateway 신뢰 헤더 추가
   *   <li>사용자 식별 정보 및 권한 정보 헤더 주입
   * </ul>
   *
   * <p>내부 서비스는 JWT를 직접 파싱하지 않고, Gateway가 주입한 헤더만을 신뢰하여 인가 처리를 수행합니다.
   */
  private ServerWebExchange enrichExchangeWithJwt(
      ServerWebExchange exchange, org.springframework.security.oauth2.jwt.Jwt jwt) {
    List<String> roles = jwt.getClaimAsStringList("roles");

    return exchange
        .mutate()
        .request(
            req ->
                req.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                    .header(HEADER_GATEWAY_TRUSTED, "true")
                    .header(HEADER_CLIENT_TYPE, "USER")
                    .header(HEADER_USER_ID, jwt.getSubject())
                    .header(HEADER_USER_NICKNAME, encode(jwt.getClaimAsString("nickname")))
                    .header(HEADER_USER_ROLES, roles == null ? "" : String.join(",", roles)))
        .build();
  }

  /**
   * HTTP 헤더 전달을 위한 UTF-8 URL 인코딩 처리.
   *
   * <p>헤더 값은 ASCII 범위를 벗어날 수 있으므로 안전한 전송을 위해 URL 인코딩을 수행합니다.
   */
  private String encode(String value) {
    return value == null ? "" : URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
