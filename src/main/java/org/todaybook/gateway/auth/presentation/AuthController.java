package org.todaybook.gateway.auth.presentation;

import jakarta.validation.Valid;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.todaybook.gateway.auth.application.AuthService;
import org.todaybook.gateway.auth.application.exception.UnauthorizedException;
import org.todaybook.gateway.auth.infrastructure.refresh.RefreshTokenProperties;
import org.todaybook.gateway.auth.presentation.dto.LoginRequest;
import org.todaybook.gateway.auth.presentation.dto.TokenResponse;
import reactor.core.publisher.Mono;

/**
 * 인증(Auth) 관련 HTTP API를 제공하는 Presentation Layer 컨트롤러입니다.
 *
 * <p>이 계층의 책임은 다음으로 한정됩니다.
 *
 * <ul>
 *   <li>HTTP 요청/응답 모델 변환
 *   <li>Refresh Token을 Cookie로 설정/삭제
 *   <li>비즈니스 예외를 HTTP 의미로 변환
 * </ul>
 *
 * <p>인증 정책, 토큰 검증/무효화 로직은 {@link AuthService}에 위임합니다.
 */
@RequestMapping("/api/v1/auth")
@RestController
@EnableConfigurationProperties(RefreshTokenProperties.class)
@RequiredArgsConstructor
public class AuthController {

  /** Refresh Token을 저장하는 HttpOnly Cookie 이름 */
  private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

  /**
   * Refresh Token Cookie가 전송되는 경로.
   *
   * <p>인증 관련 엔드포인트로만 전송되도록 제한하여 쿠키 노출 범위를 최소화합니다.
   */
  private static final String REFRESH_COOKIE_PATH = "/api/v1/auth";

  /** Refresh Token 만료 정책(TTL)을 담고 있는 설정 객체 */
  private final RefreshTokenProperties refreshTokenProperties;

  /** 인증 유스케이스를 담당하는 Application Service */
  private final AuthService authService;

  /**
   * 로그인 API.
   *
   * <p>OAuth 인증 이후 전달받은 authCode를 기반으로 로그인을 수행합니다.
   *
   * <ul>
   *   <li>Access Token은 응답 Body로 반환
   *   <li>Refresh Token은 HttpOnly Cookie로 설정
   * </ul>
   *
   * <p>Refresh Token은 JavaScript에서 접근할 수 없으며, 이후 재발급 요청 시 자동으로 전송됩니다.
   */
  @PostMapping("/login")
  public Mono<TokenResponse> login(
      @RequestBody @Valid LoginRequest request, ServerHttpResponse response) {

    return authService
        .loginWithAuthCode(request.authCode())
        .doOnNext(issuedToken -> setRefreshTokenCookie(response, issuedToken.refreshToken()))
        .map(TokenResponse::from);
  }

  /**
   * 로그아웃 API.
   *
   * <p>로그아웃은 "클라이언트 세션 종료 요청"으로 취급하며, 다음 정책을 따릅니다.
   *
   * <ul>
   *   <li>Refresh Token 쿠키 유무와 관계없이 항상 성공
   *   <li>서버의 Refresh Token 무효화는 best-effort
   *   <li>서버 처리 실패 여부와 관계없이 클라이언트 쿠키는 반드시 삭제
   * </ul>
   *
   * <p>이로써 로그아웃 API는 idempotent 하게 동작합니다.
   */
  @PostMapping("/logout")
  public Mono<Void> logout(
      @CookieValue(value = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
      ServerHttpResponse response) {

    Mono<Void> serverLogoutAttempt =
        StringUtils.hasText(refreshToken)
            ? authService.logout(refreshToken).onErrorResume(e -> Mono.empty())
            : Mono.empty();

    return serverLogoutAttempt.doFinally(sig -> deleteRefreshTokenCookie(response)).then();
  }

  /**
   * Access Token 재발급 API.
   *
   * <p>HttpOnly Cookie로 전달된 Refresh Token을 검증한 뒤, 새로운 Access Token과 Refresh Token을 발급합니다.
   *
   * <p>Refresh Token이 없는 경우는 "인증 불가"로 간주하여 명시적으로 401 Unauthorized를 반환합니다.
   */
  @PostMapping("/refresh")
  public Mono<TokenResponse> refresh(
      @CookieValue(value = REFRESH_TOKEN_COOKIE, required = false) String refreshToken,
      ServerHttpResponse response) {

    if (!StringUtils.hasText(refreshToken)) {
      return Mono.error(new UnauthorizedException("Missing refresh token cookie"));
    }

    return authService
        .refresh(refreshToken)
        .doOnNext(issuedToken -> setRefreshTokenCookie(response, issuedToken.refreshToken()))
        .map(TokenResponse::from);
  }

  /**
   * Refresh Token을 HttpOnly Cookie로 설정합니다.
   *
   * <p>Cookie의 만료 시간은 서버의 Refresh Token TTL과 반드시 동일해야 합니다.
   */
  private void setRefreshTokenCookie(ServerHttpResponse response, String refreshToken) {
    ResponseCookie cookie =
        baseRefreshCookie(refreshToken)
            .maxAge(Duration.ofSeconds(refreshTokenProperties.getExpirationSeconds()))
            .build();

    response.addCookie(cookie);
  }

  /**
   * Refresh Token Cookie를 삭제합니다.
   *
   * <p>생성 시와 동일한 속성(path, samesite, secure 등)을 유지한 채 maxAge를 0으로 설정하여 브라우저에서 즉시 제거합니다.
   */
  private void deleteRefreshTokenCookie(ServerHttpResponse response) {
    ResponseCookie cookie = baseRefreshCookie("").maxAge(Duration.ZERO).build();
    response.addCookie(cookie);
  }

  /**
   * Refresh Token Cookie의 공통 속성을 정의합니다.
   *
   * <p>생성과 삭제 시 동일한 속성을 사용하지 않으면 브라우저에서 쿠키가 정상적으로 제거되지 않을 수 있습니다.
   */
  private ResponseCookie.ResponseCookieBuilder baseRefreshCookie(String value) {
    return ResponseCookie.from(REFRESH_TOKEN_COOKIE, value)
        .httpOnly(true) // JavaScript 접근 차단 (XSS 방어)
        .secure(true) // HTTPS 환경에서만 전송
        .sameSite("None") // 크로스 사이트 요청 허용 (프론트/백엔드 분리 대응)
        .path(REFRESH_COOKIE_PATH);
  }
}
