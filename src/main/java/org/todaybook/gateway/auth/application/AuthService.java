package org.todaybook.gateway.auth.application;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtTokenCreateCommand;
import org.todaybook.gateway.auth.infrastructure.redis.AuthCodeStore;
import org.todaybook.gateway.auth.infrastructure.redis.RefreshTokenStore;
import org.todaybook.gateway.auth.domain.JwtToken;
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
   * @return 발급된 JwtToken
   */
  public Mono<JwtToken> loginWithAuthCode(String authCode) {
    return authenticateAuthCode(authCode)
        .flatMap(userId -> authCodeStore.delete(authCode).then(createUserToken(userId)));
  }

  /**
   * refreshToken을 이용해 새로운 JWT 토큰을 재발급합니다.
   *
   * @param refreshToken 클라이언트가 보유한 refreshToken
   * @return 새로 발급된 JwtToken
   */
  public Mono<JwtToken> refresh(String refreshToken) {
    return authenticateRefreshToken(refreshToken)
        .flatMap(userId -> refreshTokenStore.delete(refreshToken).then(createUserToken(userId)));
  }

  /**
   * refreshToken을 폐기하여 로그아웃을 처리합니다.
   *
   * @param refreshToken 클라이언트가 보유한 refreshToken
   * @return 로그아웃 처리 완료 Mono
   */
  public Mono<Void> delete(String refreshToken) {
    return authenticateRefreshToken(refreshToken)
        .flatMap(userId -> refreshTokenStore.delete(refreshToken))
        .then();
  }

  /** authCode의 유효성을 검증하고 사용자 식별자를 반환합니다. */
  private Mono<String> authenticateAuthCode(String authCode) {
    return requireAuthenticationValue(authCodeStore.getKakaoId(authCode), "INVALID_AUTH_CODE");
  }

  /** refreshToken의 유효성을 검증하고 사용자 식별자를 반환합니다. */
  private Mono<String> authenticateRefreshToken(String refreshToken) {
    return requireAuthenticationValue(
        refreshTokenStore.findUserId(refreshToken), "INVALID_REFRESH_TOKEN");
  }

  /**
   * USER 권한을 가진 JWT 토큰을 생성합니다.
   *
   * <p>추후 실제 사용자 조회 로직이 추가되면 Claim 생성 책임을 이 메서드에서 확장할 수 있습니다.
   */
  private Mono<JwtToken> createUserToken(String userId) {
    return authTokenService.issue(new JwtTokenCreateCommand(userId, "USER", List.of("USER_ROLE")));
  }

  /** Mono 결과가 비어 있을 경우 UnauthorizedException을 발생시킵니다. */
  private <T> Mono<T> requireAuthenticationValue(Mono<T> source, String errorCode) {
    return source.switchIfEmpty(Mono.error(new UnauthorizedException(errorCode)));
  }
}
