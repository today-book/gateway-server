package org.todaybook.gateway.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.Infrastructure.redis.RefreshTokenStore;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class JwtProvider {

  private final JwtProperties jwtProperties;
  private SecretKey secretKey;
  private final RefreshTokenStore refreshTokenStore;

  @PostConstruct
  void init() {
    this.secretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
  }

  public Mono<JwtToken> createToken(JwtTokenCreateCommand command) {
    String accessToken = createAccessToken(command);
    String refreshToken = createRefreshToken(command.kakaoId());

    return refreshTokenStore
        .save(
            refreshToken,
            command.kakaoId(),
            Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds()))
        .thenReturn(
            new JwtToken(
                accessToken,
                refreshToken,
                "Bearer",
                jwtProperties.getAccessTokenExpirationSeconds()));
  }

  private String createRefreshToken(String kakaoId) {
    return Jwts.builder()
        .subject(kakaoId)
        .issuedAt(new Date())
        .expiration(
            new Date(
                System.currentTimeMillis()
                    + Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds())
                        .toMillis()))
        .signWith(secretKey, SIG.HS256)
        .compact();
  }

  private String createAccessToken(JwtTokenCreateCommand command) {
    return Jwts.builder()
        .subject(command.kakaoId())
        .claim("nickname", command.nickname())
        .claim("roles", command.roles())
        .issuedAt(new Date())
        .expiration(
            new Date(
                System.currentTimeMillis()
                    + Duration.ofSeconds(jwtProperties.getAccessTokenExpirationSeconds())
                        .toMillis()))
        .signWith(secretKey, SIG.HS256)
        .compact();
  }
}
