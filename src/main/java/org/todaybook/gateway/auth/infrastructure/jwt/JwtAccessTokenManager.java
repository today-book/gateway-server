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
import org.todaybook.gateway.auth.application.spi.token.AccessTokenIssuer;
import org.todaybook.gateway.auth.application.token.AccessTokenIssueCommand;
import org.todaybook.gateway.auth.application.token.IssuedAccessToken;

/**
 * Access Token(JWT)의 발급 및 파싱을 담당하는 Manager 클래스입니다.
 *
 * <p>이 클래스는 오직 <b>Access Token(JWT)</b> 에 대해서만 책임을 가지며, Refresh Token과 관련된 로직은 포함하지 않습니다.
 *
 * <p>주요 책임:
 *
 * <ul>
 *   <li>JWT Access Token 생성(서명 포함)
 *   <li>JWT 파싱 및 서명 검증
 * </ul>
 *
 * <p>설계 원칙:
 *
 * <ul>
 *   <li>저장소(Redis, DB)에 대한 의존성을 갖지 않습니다.
 *   <li>만료 시간, 시크릿 키 등 정책 값은 Properties를 통해 주입받습니다.
 *   <li>JWT 표현 방식(JWS, HS256)에 대한 세부 구현을 외부로 노출하지 않습니다.
 * </ul>
 *
 * <p>Infrastructure 레이어에 위치하지만, 단순 유틸이 아닌 <b>보안 경계(Security Boundary)</b> 역할을 수행합니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Component
@EnableConfigurationProperties(AccessTokenProperties.class)
@RequiredArgsConstructor
public class JwtAccessTokenManager implements AccessTokenIssuer {

  /** Access Token(JWT) 관련 설정 값(시크릿 키, 만료 시간 등) */
  private final AccessTokenProperties props;

  /**
   * JWT 서명 및 검증에 사용되는 HMAC Secret Key입니다.
   *
   * <p>애플리케이션 초기화 시 설정 값을 기반으로 한 번만 생성되며, 이후 토큰 발급/파싱 시 재사용됩니다.
   */
  private SecretKey secretKey;

  /**
   * 애플리케이션 초기화 시 JWT 서명에 사용할 Secret Key를 준비합니다.
   *
   * <p>설정 파일에 정의된 secret 값을 기반으로 HmacSHA256 알고리즘용 {@link SecretKey}를 생성합니다.
   *
   * <p>secret 값이 유효하지 않은 경우, 애플리케이션은 즉시 실패하도록 설계하는 것이 안전합니다.
   */
  @PostConstruct
  void init() {
    String secret = props.getSecret();

    if (secret == null || secret.isBlank()) {
      throw new IllegalStateException("token.access.secret must not be blank");
    }

    // HS256은 최소 256bit(32byte) 이상 권장
    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
      throw new IllegalStateException("token.access.secret must be at least 32 bytes for HS256");
    }

    this.secretKey = Keys.hmacShaKeyFor(keyBytes);
  }

  /**
   * Access Token(JWT)을 발급합니다.
   *
   * <p>JWT에는 다음 정보가 포함됩니다.
   *
   * <ul>
   *   <li>{@code sub} : 사용자 식별자(id)
   *   <li>{@code nickname} : 사용자 표시 이름
   *   <li>{@code roles} : 사용자 권한 목록
   *   <li>{@code iat} : 토큰 발급 시각
   *   <li>{@code exp} : 토큰 만료 시각
   * </ul>
   *
   * <p>만료 시각은 설정된 Access Token TTL을 기준으로 계산되며, 발급 결과에는 클라이언트 응답용 {@code expiresInSeconds} 값도 함께
   * 반환합니다.
   *
   * @param command Access Token 생성에 필요한 사용자 식별자 및 Claim 정보
   * @return 발급된 Access Token 정보(JWT 문자열 + 만료 시간)
   */
  @Override
  public IssuedAccessToken issue(AccessTokenIssueCommand command) {
    String jwtToken =
        Jwts.builder()
            .subject(command.userId())
            .claim("nickname", command.nickname())
            .claim("roles", command.roles())
            .issuedAt(new Date())
            .expiration(
                new Date(
                    System.currentTimeMillis()
                        + Duration.ofSeconds(props.getExpirationSeconds()).toMillis()))
            .signWith(secretKey, SIG.HS256)
            .compact();

    return new IssuedAccessToken(jwtToken, props.getExpirationSeconds());
  }

  /**
   * JWT 문자열을 파싱하여 Claims 정보를 반환합니다.
   *
   * <p>이 과정에서 다음 검증이 자동으로 수행됩니다.
   *
   * <ul>
   *   <li>JWT 서명 검증
   *   <li>토큰 만료(exp) 검증
   * </ul>
   *
   * <p>토큰이 유효하지 않거나 서명 검증에 실패한 경우 {@link io.jsonwebtoken.JwtException} 계열 예외가 발생합니다.
   *
   * @param token 파싱할 JWT 문자열(Access Token)
   * @return JWT에 포함된 Claims
   */
  public Claims parse(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
