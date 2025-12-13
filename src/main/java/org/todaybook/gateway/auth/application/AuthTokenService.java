package org.todaybook.gateway.auth.application;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.application.refresh.IssuedRefreshToken;
import org.todaybook.gateway.auth.application.refresh.RefreshTokenManager;
import org.todaybook.gateway.auth.application.spi.token.AccessTokenIssuer;
import org.todaybook.gateway.auth.application.token.AccessTokenIssueCommand;
import org.todaybook.gateway.auth.application.token.IssuedAccessToken;
import org.todaybook.gateway.auth.infrastructure.jwt.JwtAccessTokenManager;
import reactor.core.publisher.Mono;

/**
 * 토큰 발급/재발급/폐기 유스케이스를 담당하는 Application Service입니다.
 *
 * <p>이 클래스는 토큰 관련 흐름을 조합(오케스트레이션)하는 역할만 수행하며, 토큰 생성/검증/회전/저장 같은 세부 정책은 각각의 Manager에게 위임합니다.
 *
 * <ul>
 *   <li>{@link JwtAccessTokenManager}: Access Token(JWT) 생성 및 파싱/검증
 *   <li>{@link RefreshTokenManager}: Refresh Token 발급/회전/폐기 및 저장 정책
 * </ul>
 *
 * <p>중요한 설계 원칙:
 *
 * <ul>
 *   <li>본 클래스는 Properties(만료 시간/시크릿 등)를 직접 참조하지 않습니다.
 *   <li>저장소(Store/Redis)에 직접 접근하지 않고 Manager를 통해서만 접근합니다.
 *   <li>API 응답에 필요한 expiresIn 값은 Manager가 계산하여 반환한 값을 사용합니다.
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class AuthTokenService {

  /** Access Token(JWT) 발급 로직을 캡슐화한 SPI */
  private final AccessTokenIssuer accessTokenIssuer;

  /** Refresh Token 발급/회전/폐기 및 저장 정책을 캡슐화한 Manager */
  private final RefreshTokenManager refreshTokenManager;

  /**
   * 사용자 식별자를 기반으로 Access Token과 Refresh Token을 발급합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>Access Token(JWT) 발급
   *   <li>Refresh Token 발급 및 저장(해싱 + TTL 적용 포함)
   *   <li>클라이언트 응답 DTO로 조합
   * </ol>
   *
   * <p>expiresIn 값은 일반적으로 Access Token의 TTL을 의미하며, Refresh Token TTL이 필요하다면 별도 필드로 분리하는 것을 권장합니다.
   *
   * @param userId 인증된 사용자 식별자
   * @return 발급된 토큰 정보(Access/Refresh + expiresIn)
   */
  public Mono<IssuedToken> issue(String userId) {
    // TODO: 실제 운영에서는 role/nickname 등 Claim 구성은 사용자 서비스 조회 또는 정책에 맞게 구성
    AccessTokenIssueCommand command =
        new AccessTokenIssueCommand(userId, "USER", List.of("USER_ROLE"));

    // Access Token 발급(동기) - 필요 시 Mono.fromSupplier로 감싸 예외/스케줄링을 일관되게 처리할 수 있습니다.
    IssuedAccessToken accessToken = accessTokenIssuer.issue(command);

    // Refresh Token 발급(비동기) - 내부에서 해시 저장 및 TTL 적용까지 수행
    Mono<IssuedRefreshToken> refreshTokenMono = refreshTokenManager.issue(userId);

    return refreshTokenMono.map(
        refreshToken ->
            new IssuedToken(
                accessToken.token(), refreshToken.token(), accessToken.expiresInSeconds()));
  }

  /**
   * Refresh Token을 이용해 Access Token과 Refresh Token을 재발급합니다.
   *
   * <p>기존 Refresh Token은 재사용 방지를 위해 회전(rotation)되며, 유효하지 않거나 이미 사용된 토큰인 경우 인증 오류가 발생합니다.
   *
   * <p>rotate 결과로부터 userId를 획득하여 Access Token을 다시 발급합니다. (별도 verify 없이 rotate를 검증 수단으로 사용하는 설계)
   *
   * @param oldRawRefreshToken 클라이언트가 보유한 기존 Refresh Token 원문
   * @return 새로 발급된 토큰 정보(Access/Refresh + expiresIn)
   */
  public Mono<IssuedToken> refresh(String oldRawRefreshToken) {
    return refreshTokenManager
        .rotate(oldRawRefreshToken)
        .map(
            rotated -> {
              String userId = rotated.userId();

              // TODO: 실제 운영에서는 role/nickname 등 Claim 구성은 사용자 서비스 조회 또는 정책에 맞게 구성
              AccessTokenIssueCommand command =
                  new AccessTokenIssueCommand(userId, "USER", List.of("USER_ROLE"));

              IssuedAccessToken access = accessTokenIssuer.issue(command);

              return new IssuedToken(
                  access.token(),
                  rotated.token(), // 새로 발급된 Refresh Token
                  access.expiresInSeconds()); // expiresIn은 Access Token 기준
            });
  }

  /**
   * Refresh Token을 폐기합니다(로그아웃).
   *
   * <p>폐기 요청은 명령(Command) 성격이며, 이미 만료되었거나 존재하지 않는 경우에도 정상 종료로 처리할 수 있습니다.
   *
   * @param refreshToken 클라이언트가 보유한 Refresh Token 원문
   * @return 폐기 처리 완료 신호
   */
  public Mono<Void> revokeRefreshToken(String refreshToken) {
    return refreshTokenManager.revoke(refreshToken);
  }
}
