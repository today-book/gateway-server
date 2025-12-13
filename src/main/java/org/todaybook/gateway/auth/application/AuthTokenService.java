package org.todaybook.gateway.auth.application;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtProperties;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtProvider;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtTokenCreateCommand;
import org.todaybook.gateway.auth.infrastructure.redis.RefreshTokenStore;
import reactor.core.publisher.Mono;

/**
 * 인증 토큰 발급 및 저장 정책을 담당하는 서비스입니다.
 *
 * <p>이 서비스는 인증이 완료된 사용자에 대해
 * Access Token(JWT)과 Refresh Token(UUID)을 생성하고,
 * Refresh Token을 Redis에 저장하는 책임을 가집니다.
 *
 * <p>AuthService는 이 클래스의 내부 구현을 알 필요 없이
 * 토큰 발급 결과(JwtToken)만을 사용합니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Service
@RequiredArgsConstructor
public class AuthTokenService {

  /** JWT 생성 및 파싱을 담당하는 Provider입니다. */
  private final JwtProvider jwtProvider;

  /** Refresh Token의 저장 및 회전 정책을 담당하는 저장소입니다. */
  private final RefreshTokenStore refreshTokenStore;

  /** JWT 만료 시간 및 설정 값을 제공하는 Properties입니다. */
  private final JwtProperties jwtProperties;

  /**
   * 신규 로그인 시 Access Token과 Refresh Token을 발급합니다.
   *
   * <p>Refresh Token은 UUID 기반으로 생성되며,
   * Redis에 사용자 식별자와 함께 저장됩니다.
   *
   * @param userId 인증이 완료된 사용자 식별자
   * @return 발급된 IssuedToken
   */
  public Mono<IssuedToken> issue(String userId) {
    JwtTokenCreateCommand command =
        new JwtTokenCreateCommand(userId, "USER", List.of("USER_ROLE"));

    String accessToken = createAccessToken(command);
    String refreshToken = createRefreshToken();

    return refreshTokenStore
        .save(
            refreshToken,
            command.userId(),
            Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds()))
        .flatMap(
            saved ->
                saved
                    ? Mono.just(
                    new IssuedToken(
                        accessToken,
                        refreshToken,
                        "Bearer",
                        jwtProperties.getAccessTokenExpirationSeconds()))
                    : Mono.error(
                        new IllegalStateException("Failed to persist refresh token")));
  }

  /**
   * Refresh Token 재발급 시 Access Token만 새로 발급합니다.
   *
   * <p>Refresh Token은 이미 회전(rotation)되어 저장된 상태이므로,
   * 이 메서드는 Access Token 생성 책임만 가집니다.
   *
   * @param userId Refresh Token을 통해 검증된 사용자 식별자
   * @param refreshToken 새로 발급된 Refresh Token
   * @return 새로 구성된 IssuedToken
   */
  public IssuedToken issueWithRefresh(String userId, String refreshToken) {
    String accessToken =
        createAccessToken(
            new JwtTokenCreateCommand(userId, "USER", List.of("USER_ROLE")));

    return new IssuedToken(
        accessToken,
        refreshToken,
        "Bearer",
        accessTokenExpireSeconds());
  }

  /**
   * Access Token(JWT)을 생성합니다.
   *
   * @param command Access Token 생성에 필요한 사용자 정보
   * @return 서명된 Access Token 문자열
   */
  public String createAccessToken(JwtTokenCreateCommand command) {
    return jwtProvider.createAccessToken(command);
  }

  /**
   * Refresh Token(UUID)을 생성합니다.
   *
   * <p>Refresh Token은 서버 상태(Redis)에 저장되며,
   * 자체적으로 의미를 가지지 않는 랜덤 값입니다.
   *
   * @return 새로 생성된 Refresh Token
   */
  public String createRefreshToken() {
    return jwtProvider.createRefreshToken();
  }

  /**
   * Refresh Token의 만료 시간을 반환합니다.
   *
   * @return Refresh Token TTL
   */
  public Duration refreshTokenTtl() {
    return Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds());
  }

  /**
   * Access Token의 만료 시간을 초 단위로 반환합니다.
   *
   * @return Access Token 만료 시간(초)
   */
  public long accessTokenExpireSeconds() {
    return jwtProperties.getAccessTokenExpirationSeconds();
  }
}
