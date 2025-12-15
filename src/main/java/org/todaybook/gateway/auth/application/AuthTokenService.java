package org.todaybook.gateway.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.AuthenticatedUser;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.application.refresh.IssuedRefreshToken;
import org.todaybook.gateway.auth.application.refresh.RefreshTokenManager;
import org.todaybook.gateway.auth.application.refresh.RotatedRefreshToken;
import org.todaybook.gateway.auth.application.spi.token.AccessTokenIssuer;
import org.todaybook.gateway.auth.application.token.AccessTokenIssueCommand;
import org.todaybook.gateway.auth.application.token.IssuedAccessToken;
import reactor.core.publisher.Mono;

/**
 * 토큰 발급/재발급/폐기 유스케이스를 담당하는 Application Service입니다.
 *
 * <p>이 클래스는 토큰 관련 흐름을 조합(오케스트레이션)하는 역할만 수행하며, 토큰 생성/검증/회전/저장 같은 세부 정책은 각각의 Manager에게 위임합니다.
 *
 * <ul>
 *   <li>{@link AccessTokenIssuer}: Access Token(JWT) 생성 및 파싱/검증
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
   * 신규 로그인 또는 최초 인증 시 토큰을 발급합니다.
   *
   * <p>설계 의도:
   *
   * <ul>
   *   <li>Access Token은 동기적으로 즉시 발급합니다.
   *   <li>Refresh Token은 저장소 접근이 필요하므로 비동기(Mono)로 발급합니다.
   *   <li>두 토큰의 발급 책임을 분리하되, 최종 응답 DTO는 여기서 조합합니다.
   * </ul>
   *
   * <p>Access Token 발급이 순수 계산(JWT 서명)이라는 전제 하에 reactive 체인으로 감싸지 않고 동기 호출을 허용합니다.
   *
   * @param user 인증이 완료된 사용자
   * @return 발급된 Access/Refresh Token과 만료 정보를 포함한 결과
   */
  public Mono<IssuedToken> issue(AuthenticatedUser user) {
    AccessTokenIssueCommand command =
        new AccessTokenIssueCommand(user.userId(), user.nickname(), user.roles());

    IssuedAccessToken accessToken = accessTokenIssuer.issue(command);

    Mono<IssuedRefreshToken> refreshTokenMono = refreshTokenManager.issue(user.userId());

    return refreshTokenMono.map(
        refreshToken ->
            new IssuedToken(
                accessToken.token(), refreshToken.token(), accessToken.expiresInSeconds()));
  }

  /**
   * 기존 Refresh Token을 회전(rotation)합니다.
   *
   * <p>보안 정책상 Refresh Token은 재사용을 허용하지 않으며, 유효한 토큰이 요청되면 새로운 토큰으로 교체하고 기존 토큰은 즉시 무효화합니다.
   *
   * <p>이 메서드는 Refresh Token 자체의 유효성 및 저장소 상태만을 다루며, 사용자 로딩이나 Access Token 재발급은 호출 측에서 명시적으로 수행하도록
   * 분리합니다.
   *
   * @param oldRawRefreshToken 클라이언트가 보유한 기존 Refresh Token 원문
   * @return 회전된 Refresh Token과 사용자 식별자를 포함한 결과
   */
  public Mono<RotatedRefreshToken> rotate(String oldRawRefreshToken) {
    return refreshTokenManager.rotate(oldRawRefreshToken);
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

  /**
   * Access Token만 단독으로 발급합니다.
   *
   * <p>사용 사례:
   *
   * <ul>
   *   <li>Refresh Token 회전 이후 Access Token만 재발급하는 경우
   *   <li>이미 인증된 사용자 컨텍스트가 존재하는 내부 흐름
   * </ul>
   *
   * <p>Refresh Token 발급/저장과 무관한 순수 토큰 생성 유스케이스이므로 reactive 타입을 사용하지 않습니다.
   *
   * @param user 인증된 사용자
   * @return 새로 발급된 Access Token
   */
  public IssuedAccessToken issueAccessToken(AuthenticatedUser user) {
    AccessTokenIssueCommand command =
        new AccessTokenIssueCommand(user.userId(), user.nickname(), user.roles());

    return accessTokenIssuer.issue(command);
  }
}
