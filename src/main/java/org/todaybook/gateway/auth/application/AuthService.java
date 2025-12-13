package org.todaybook.gateway.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.application.dto.IssuedToken;
import org.todaybook.gateway.auth.application.spi.AuthCodeConsumer;
import reactor.core.publisher.Mono;

/**
 * 인증(Authentication) 유스케이스를 조율하는 Application Service입니다.
 *
 * <p>이 클래스는 인증 흐름의 진입점으로서 다음 책임을 가집니다.
 *
 * <ul>
 *   <li>OAuth 인증 이후 발급된 authCode를 검증하고 소비
 *   <li>Access Token / Refresh Token 발급 유스케이스 위임
 *   <li>Refresh Token 기반 재발급 유스케이스 위임
 *   <li>로그아웃 시 Refresh Token 폐기 처리
 * </ul>
 *
 * <p>토큰 생성/회전/폐기와 같은 세부 정책은 {@link AuthTokenService}에 위임하며, 본 클래스는 <b>인증 흐름을 조율</b>하는 역할만 수행합니다.
 *
 * <p>이 클래스는 Infrastructure(Redis, JWT 등)에 대한 세부 구현을 직접 다루지 않고, 유스케이스 수준의 흐름만을 책임집니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Service
@RequiredArgsConstructor
public class AuthService {

  /**
   * OAuth 로그인 과정에서 발급된 authCode를 소비하는 저장소입니다.
   *
   * <p>authCode는 일회성 인증 수단으로, 검증과 동시에 반드시 소비(delete)되어야 합니다.
   */
  private final AuthCodeConsumer authCodeConsumer;

  /** Access Token / Refresh Token 발급 및 재발급 정책을 담당하는 서비스입니다. */
  private final AuthTokenService authTokenService;

  /**
   * OAuth 로그인 이후 전달받은 authCode를 이용해 로그인 처리 후 토큰을 발급합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>authCode 유효성 검증 및 즉시 소비
   *   <li>인증된 사용자 식별자(userId) 확보
   *   <li>Access Token / Refresh Token 발급 위임
   * </ol>
   *
   * @param authCode OAuth 로그인 이후 발급된 일회성 인증 코드
   * @return 발급된 Access Token / Refresh Token 정보
   */
  public Mono<IssuedToken> loginWithAuthCode(String authCode) {
    return verifyAndConsumeAuthCode(authCode).flatMap(authTokenService::issue);
  }

  /**
   * Refresh Token을 이용해 Access Token과 Refresh Token을 재발급합니다.
   *
   * <p>기존 Refresh Token은 재사용 방지를 위해 원자적으로 회전(rotation)되며, 유효하지 않거나 이미 사용된 토큰인 경우 인증 오류를 반환합니다.
   *
   * @param refreshToken 클라이언트가 보유한 Refresh Token 원문
   * @return 새로 발급된 Access Token / Refresh Token 정보
   */
  public Mono<IssuedToken> refresh(String refreshToken) {
    return authTokenService.refresh(refreshToken);
  }

  /**
   * 로그아웃을 처리합니다.
   *
   * <p>클라이언트가 보유한 Refresh Token을 폐기하여 이후 토큰 재발급이 불가능하도록 합니다.
   *
   * <p>Refresh Token이 이미 만료되었거나 존재하지 않는 경우에도 로그아웃 요청은 정상 처리됩니다.
   *
   * @param refreshToken 클라이언트가 보유한 Refresh Token 원문
   * @return 로그아웃 처리 완료 신호
   */
  public Mono<Void> logout(String refreshToken) {
    return authTokenService.revokeRefreshToken(refreshToken);
  }

  /**
   * authCode를 인증 수단으로 검증하고 즉시 소비하여 사용자 식별자를 반환합니다.
   *
   * <p>authCode는 일회성 인증 수단이므로, 조회와 동시에 삭제(get-and-delete)되어야 합니다.
   *
   * <p>authCode가 유효하지 않거나 이미 사용된 경우 인증 실패로 간주하여 예외를 발생시킵니다.
   *
   * @param authCode OAuth 로그인 이후 전달받은 인증 코드
   * @return 인증된 사용자 식별자(userId)
   */
  private Mono<String> verifyAndConsumeAuthCode(String authCode) {
    return authCodeConsumer
        .getAndDeleteKakaoId(authCode)
        .switchIfEmpty(Mono.error(new UnauthorizedException("INVALID_AUTH_CODE")));
  }
}
