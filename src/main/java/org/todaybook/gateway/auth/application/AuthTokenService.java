package org.todaybook.gateway.auth.application;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtProperties;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtProvider;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtTokenCreateCommand;
import org.todaybook.gateway.auth.Infrastructure.redis.RefreshTokenStore;
import org.todaybook.gateway.auth.domain.JwtToken;
import reactor.core.publisher.Mono;

/**
 * 인증 토큰 발급 및 저장 정책을 담당하는 서비스입니다.
 *
 * <p>Access Token / Refresh Token 생성 후 Refresh Token을 저장하고, 최종적으로 클라이언트에 전달할 JwtToken을 구성합니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Service
@RequiredArgsConstructor
public class AuthTokenService {

  private final JwtProvider jwtProvider;
  private final RefreshTokenStore refreshTokenStore;
  private final JwtProperties jwtProperties;

  public Mono<JwtToken> issue(JwtTokenCreateCommand command) {
    String accessToken = jwtProvider.createAccessToken(command);
    String refreshToken = jwtProvider.createRefreshToken(command.userId());

    return refreshTokenStore
        .save(
            refreshToken,
            command.userId(),
            Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds()))
        .flatMap(
            saved ->
                saved
                    ? Mono.just(
                        new JwtToken(
                            accessToken,
                            refreshToken,
                            "Bearer",
                            jwtProperties.getAccessTokenExpirationSeconds()))
                    : Mono.error(new IllegalStateException("Failed to persist refresh token")));
  }
}
