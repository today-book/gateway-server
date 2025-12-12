package org.todaybook.gateway.security.jwt;

import static org.todaybook.gateway.security.exception.TokenValidationErrorCode.EMPTY_TOKEN;
import static org.todaybook.gateway.security.exception.TokenValidationErrorCode.EXPIRED_TOKEN;
import static org.todaybook.gateway.security.exception.TokenValidationErrorCode.INVALID_TOKEN_FORMAT;
import static org.todaybook.gateway.security.exception.TokenValidationErrorCode.INVALID_TOKEN_SIGNATURE;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.security.exception.TokenValidationException;
import reactor.core.publisher.Mono;

@Slf4j
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

  public JwtToken createToken(JwtTokenCreateCommand command) {
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

  public void validateOrThrow(String token) {
    try {
      Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);

    } catch (ExpiredJwtException e) {
      throw new TokenValidationException(EXPIRED_TOKEN);

    } catch (SignatureException e) {
      throw new TokenValidationException(INVALID_TOKEN_SIGNATURE);

    } catch (MalformedJwtException | UnsupportedJwtException e) {
      throw new TokenValidationException(INVALID_TOKEN_FORMAT);

    } catch (IllegalArgumentException e) {
      throw new TokenValidationException(EMPTY_TOKEN);
    }
  }

  public Claims getClaims(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
