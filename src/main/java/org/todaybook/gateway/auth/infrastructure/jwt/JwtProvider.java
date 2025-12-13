package org.todaybook.gateway.auth.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * JWT 생성 및 파싱을 담당하는 Provider 클래스입니다.
 *
 * <p>이 클래스는 Access Token(JWT)의 생성 및 파싱 책임만을 가지며, Refresh Token은 서버 상태 기반(UUID) 토큰으로 생성합니다.
 *
 * <p>저장소(Redis, DB)에 대한 의존성은 없으며, 순수하게 토큰 생성/검증 로직만을 캡슐화합니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Component
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class JwtProvider {

  /** JWT 관련 설정 값을 담고 있는 Properties 객체입니다. */
  private final JwtProperties jwtProperties;

  /** JWT 서명 및 검증에 사용되는 HMAC Secret Key입니다. */
  private SecretKey secretKey;

  /**
   * 애플리케이션 초기화 시 JWT 서명에 사용할 Secret Key를 생성합니다.
   *
   * <p>설정 파일에 정의된 secret 값을 기반으로 HMAC-SHA256 알고리즘용 키를 초기화합니다.
   */
  @PostConstruct
  void init() {
    this.secretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Access Token(JWT)을 생성합니다.
   *
   * <p>사용자 식별자와 권한 정보를 Claim으로 포함하며, 설정된 만료 시간을 기준으로 토큰을 발급합니다.
   *
   * @param command Access Token 생성에 필요한 사용자 정보 및 Claim 데이터
   * @return 서명된 Access Token 문자열
   */
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

  /**
   * Refresh Token을 생성합니다.
   *
   * <p>Refresh Token은 서버 상태(Redis)에 저장되는 UUID 기반 토큰으로, 별도의 Claim이나 서명 정보를 포함하지 않습니다.
   *
   * @return 새로 생성된 Refresh Token(UUID 문자열)
   */
  public String createRefreshToken() {
    return UUID.randomUUID().toString();
  }

  /**
   * JWT 문자열을 파싱하여 Claim 정보를 반환합니다.
   *
   * <p>서명 검증에 실패하거나 토큰이 유효하지 않은 경우 예외가 발생합니다.
   *
   * @param token 파싱할 JWT 문자열
   * @return JWT에 포함된 Claims 객체
   */
  public Claims parse(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
