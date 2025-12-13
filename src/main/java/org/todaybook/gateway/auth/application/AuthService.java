package org.todaybook.gateway.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.infrastructure.redis.AuthCodeStore;
import org.todaybook.gateway.auth.infrastructure.redis.RefreshTokenStore;
import reactor.core.publisher.Mono;

/**
 * 인증 관련 비즈니스 로직을 담당하는 서비스 클래스입니다.
 *
 * <p>authCode 기반 로그인, refreshToken 기반 재발급, refreshToken 폐기를 통한 로그아웃을 처리합니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Service
@RequiredArgsConstructor
public class AuthService {

  private final RefreshTokenStore refreshTokenStore;
  private final AuthCodeStore authCodeStore;
  private final AuthTokenService authTokenService;

  /**
   * authCode를 이용해 로그인하고 JWT 토큰을 발급합니다.
   *
   * @param authCode OAuth 로그인 이후 발급된 일회성 인증 코드
   * @return 발급된 IssuedToken
   */
  public Mono<IssuedToken> loginWithAuthCode(String authCode) {
    return authenticateAndConsumeAuthCode(authCode)
        .flatMap(authTokenService::issue);
  }

  /**
   * refreshToken을 이용해 Access Token과 Refresh Token을 재발급합니다.
   *
   * <p>기존 refreshToken은 원자적으로 회전되며,
   * 유효하지 않은 경우 인증 오류를 반환합니다.
   *
   * @param refreshToken 클라이언트가 보유한 refreshToken(UUID)
   * @return 새로 발급된 IssuedToken
   */
  public Mono<IssuedToken> refresh(String refreshToken) {
    String newRefreshToken = authTokenService.createRefreshToken();

    return refreshTokenStore
        .rotate(refreshToken, newRefreshToken, authTokenService.refreshTokenTtl())
        .switchIfEmpty(Mono.error(new UnauthorizedException("INVALID_REFRESH_TOKEN")))
        .map(userId -> authTokenService.issueWithRefresh(userId, newRefreshToken));
  }
  /**
   * refreshToken을 폐기하여 로그아웃을 처리합니다.
   *
   * <p>refreshToken이 존재하지 않거나 이미 만료된 경우에도
   * 로그아웃 요청은 성공으로 처리됩니다.
   *
   * @param refreshToken 클라이언트가 보유한 refreshToken
   * @return 로그아웃 처리 완료 Mono
   */
  public Mono<Void> logout(String refreshToken) {
    return refreshTokenStore.delete(refreshToken).then();
  }

  /**
   * authCode를 인증 수단으로 검증하고 즉시 소비하여 사용자 식별자를 반환합니다.
   *
   * <p>authCode가 유효하지 않거나 이미 사용된 경우 인증 오류를 발생시킵니다.
   *
   */
  private Mono<String> authenticateAndConsumeAuthCode(String authCode) {
    return authCodeStore
        .getAndDeleteKakaoId(authCode)
        .switchIfEmpty(Mono.error(new UnauthorizedException("INVALID_AUTH_CODE")));
  }
}
