package org.todaybook.gateway.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeConsumer;
import org.todaybook.gateway.auth.application.token.IssuedAccessToken;
import reactor.core.publisher.Mono;

/**
 * 인증 관련 유스케이스를 조합하는 애플리케이션 서비스.
 *
 * <p>이 클래스는 OAuth 코드 소비, 사용자 식별(조회/생성), 토큰 발급/회전/폐기 흐름을 순서대로 연결하며, 개별 정책 및 저장소 접근은 하위 서비스/포트에
 * 위임합니다.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

  /**
   * 인증 코드(payload)를 조회한 뒤 즉시 삭제하는 포트.
   *
   * <p>인증 코드는 일회성 자원이므로, 조회와 삭제가 원자적으로 보장되지 않으면 재사용 공격 위험이 생길 수 있습니다.
   */
  private final AuthCodeConsumer authCodeConsumer;

  /** 액세스/리프레시 토큰의 발급, 회전(rotation), 폐기를 담당합니다. */
  private final AuthTokenService authTokenService;

  /**
   * OAuth 사용자 정보로부터 내부 사용자 식별자를 해결합니다.
   *
   * <p>기존 사용자는 조회하고, 신규 사용자는 생성하는 정책을 포함할 수 있습니다.
   */
  private final UserIdentityService userIdentityService;

  /**
   * OAuth 인증 코드로 로그인합니다.
   *
   * <p>흐름:
   *
   * <ol>
   *   <li>인증 코드를 소비(조회 + 즉시 삭제)하여 재사용을 방지합니다.
   *   <li>OAuth 사용자 정보를 내부 사용자로 매핑(조회/생성)합니다.
   *   <li>해당 사용자에 대한 토큰을 발급합니다.
   * </ol>
   *
   * @param authCode OAuth 인증 코드(일회성)
   * @return 발급된 액세스/리프레시 토큰을 포함한 결과
   */
  public Mono<IssuedToken> loginWithAuthCode(String authCode) {
    return authCodeConsumer
        .getAndDeletePayload(authCode)
        .flatMap(
            payload ->
                userIdentityService
                    .resolveOrCreateFromOauth(payload)
                    .flatMap(authTokenService::issue));
  }

  /**
   * 기존 리프레시 토큰으로 토큰을 재발급합니다.
   *
   * <p>보안 정책:
   *
   * <ul>
   *   <li>리프레시 토큰은 재사용을 허용하지 않고 회전(rotation)합니다.
   *   <li>회전된 토큰의 사용자 ID로 인증된 사용자 정보를 재조회한 뒤 액세스 토큰을 발급합니다.
   * </ul>
   *
   * @param oldRefreshToken 기존 리프레시 토큰
   * @return 새 액세스 토큰과 회전된 리프레시 토큰을 포함한 결과
   */
  public Mono<IssuedToken> refresh(String oldRefreshToken) {
    return authTokenService
        .rotate(oldRefreshToken)
        .flatMap(
            rotated ->
                userIdentityService
                    .loadAuthenticatedUser(rotated.userId())
                    .map(
                        user -> {
                          IssuedAccessToken access = authTokenService.issueAccessToken(user);
                          return new IssuedToken(
                              access.token(), rotated.token(), access.expiresInSeconds());
                        }));
  }

  /**
   * 로그아웃 처리로 리프레시 토큰을 폐기합니다.
   *
   * <p>액세스 토큰은 일반적으로 상태를 저장하지 않으므로 즉시 무효화 대신, 리프레시 토큰 폐기로 이후 재발급을 차단합니다.
   *
   * @param refreshToken 폐기할 리프레시 토큰
   * @return 폐기 처리 완료 신호
   */
  public Mono<Void> logout(String refreshToken) {
    return authTokenService.revokeRefreshToken(refreshToken);
  }
}
