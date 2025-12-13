package org.todaybook.gateway.auth.presentation;

import jakarta.validation.Valid;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.todaybook.gateway.auth.application.AuthService;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtProperties;
import org.todaybook.gateway.auth.presentation.dto.JwtToken;
import org.todaybook.gateway.auth.presentation.dto.LoginRequest;
import reactor.core.publisher.Mono;

/**
 * 인증(Auth) 전용 컨트롤러입니다.
 *
 * <p>이 컨트롤러는 다음 책임만을 가집니다.
 *
 * <ul>
 *   <li>OAuth 인증 이후 authCode를 통한 로그인 처리
 *   <li>Refresh Token 기반 Access Token 재발급
 *   <li>로그아웃 시 Refresh Token 무효화
 * </ul>
 *
 * <p>Refresh Token은 보안을 위해 HttpOnly Cookie로만 관리하며, 클라이언트(JavaScript)에서는 직접 접근할 수 없습니다.
 *
 * <p>인증 관련 API는 모두 {@code /api/v1/auth/**} 하위에 위치합니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@RequestMapping("/api/v1/auth")
@RestController
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class AuthController {

  /** Refresh Token을 저장하기 위한 쿠키 이름입니다. */
  private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

  /**
   * JWT 만료 시간 등 토큰 정책을 담고 있는 설정 객체입니다.
   *
   * <p>Cookie의 maxAge와 서버의 Refresh Token TTL을 동일한 기준으로 유지하기 위해 사용됩니다.
   */
  private final JwtProperties jwtProperties;

  /** 인증 관련 비즈니스 로직을 담당하는 서비스입니다. */
  private final AuthService authService;

  /**
   * 로그인 API (공개 API).
   *
   * <p>OAuth 인증 이후 전달받은 authCode를 기반으로 로그인을 수행합니다.
   *
   * <ul>
   *   <li>Access Token은 응답 Body(JSON)로 반환합니다.
   *   <li>Refresh Token은 HttpOnly Cookie로 설정합니다.
   * </ul>
   *
   * <p>Refresh Token은 클라이언트에서 직접 접근하지 않으며, 이후 토큰 재발급 시 자동으로 전송됩니다.
   */
  @PostMapping("/login")
  public Mono<JwtToken> login(
      @RequestBody @Valid LoginRequest request, ServerHttpResponse response) {
    return authService
        .loginWithAuthCode(request.authCode())
        .doOnNext(issuedToken -> addRefreshTokenCookie(response, issuedToken.refreshToken()))
        .map(JwtToken::from);
  }

  /**
   * 로그아웃 API.
   *
   * <p>HttpOnly Cookie에 저장된 Refresh Token을 기준으로 서버(Redis)에 저장된 토큰을 무효화합니다.
   *
   * <p>로그아웃 이후에는 Refresh Token 쿠키를 즉시 삭제하여, 이후 재발급 요청이 불가능하도록 처리합니다.
   */
  @PostMapping("/logout")
  public Mono<Void> logout(
      @CookieValue(REFRESH_TOKEN_COOKIE) String refreshToken, ServerHttpResponse response) {
    return authService.logout(refreshToken).doOnSuccess(v -> deleteRefreshTokenCookie(response));
  }

  /**
   * Access Token 재발급 API.
   *
   * <p>HttpOnly Cookie로 전달된 Refresh Token을 검증한 뒤, 새로운 Access Token과 Refresh Token을 발급합니다.
   *
   * <p>보안을 위해 Refresh Token은 회전(Rotate) 방식으로 재발급되며, 기존 Refresh Token은 즉시 무효화됩니다.
   */
  @PostMapping("/refresh")
  public Mono<JwtToken> refresh(
      @CookieValue(REFRESH_TOKEN_COOKIE) String refreshToken, ServerHttpResponse response) {
    return authService
        .refresh(refreshToken)
        .doOnNext(issuedToken -> addRefreshTokenCookie(response, issuedToken.refreshToken()))
        .map(JwtToken::from);
  }

  /**
   * Refresh Token을 HttpOnly Cookie로 설정합니다.
   *
   * <ul>
   *   <li>HttpOnly: JavaScript 접근 차단
   *   <li>Secure: HTTPS 환경에서만 전송
   *   <li>SameSite=None: Cross-site 요청 허용
   *   <li>Path: /api/v1/auth 하위 요청에서만 전송
   * </ul>
   *
   * <p>Cookie의 만료 시간은 서버의 Refresh Token TTL과 반드시 동일하게 유지되어야 합니다.
   */
  private void addRefreshTokenCookie(ServerHttpResponse response, String refreshToken) {
    ResponseCookie cookie =
        ResponseCookie.from(REFRESH_TOKEN_COOKIE, refreshToken)
            .httpOnly(true)
            .secure(true)
            .sameSite("None")
            .path("/api/v1/auth")
            .maxAge(Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds()))
            .build();

    response.addCookie(cookie);
  }

  /**
   * Refresh Token 쿠키를 삭제합니다.
   *
   * <p>maxAge를 0으로 설정하여 브라우저에서 즉시 제거합니다.
   */
  private void deleteRefreshTokenCookie(ServerHttpResponse response) {
    ResponseCookie cookie =
        ResponseCookie.from(REFRESH_TOKEN_COOKIE, "").path("/api/v1/auth").maxAge(0).build();

    response.addCookie(cookie);
  }
}
