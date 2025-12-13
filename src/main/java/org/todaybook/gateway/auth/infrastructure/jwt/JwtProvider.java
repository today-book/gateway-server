package org.todaybook.gateway.auth.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * JWT 생성 및 파싱을 담당하는 Provider 클래스입니다.
 *
 * <p>Access Token과 Refresh Token의 생성 및 검증 로직만을 책임지며, 저장소(Redis, DB)에 대한 의존성은 가지지 않습니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Component
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class JwtProvider {

  private final JwtProperties jwtProperties;
  private SecretKey secretKey;

  @PostConstruct
  void init() {
    this.secretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
  }

  public String createAccessToken(JwtTokenCreateCommand command) {
    return Jwts.builder()
        .subject(command.userId())
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

  public String createRefreshToken(String userId) {
    return Jwts.builder()
        .subject(userId)
        .issuedAt(new Date())
        .expiration(
            new Date(
                System.currentTimeMillis()
                    + Duration.ofSeconds(jwtProperties.getRefreshTokenExpirationSeconds())
                        .toMillis()))
        .signWith(secretKey, SIG.HS256)
        .compact();
  }

  public Claims parse(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
