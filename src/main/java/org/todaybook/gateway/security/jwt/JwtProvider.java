package org.todaybook.gateway.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

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

  public String createToken(JwtTokenCreateCommand command) {
    return Jwts.builder()
        .subject(command.kakaoId())
        .claim("nickname", command.nickname())
        .claim("roles", command.roles())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))
        .signWith(Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes()), SIG.HS256)
        .compact();
  }

  public boolean validate(String token) {
    try {
      Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);

      return true;
    } catch (JwtException | IllegalArgumentException e) {
      return false;
    }
  }

  public Claims getClaims(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
