package org.todaybook.gateway.auth.application.refresh;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.exception.UnauthorizedException;
import org.todaybook.gateway.auth.application.spi.refresh.RefreshTokenEncoder;
import org.todaybook.gateway.auth.application.spi.refresh.RefreshTokenStore;
import org.todaybook.gateway.auth.infrastructure.refresh.RefreshTokenProperties;
import reactor.core.publisher.Mono;

/**
 * Refresh Token의 발급, 회전, 폐기 정책을 담당하는 Manager 클래스입니다.
 *
 * <p>이 클래스는 Refresh Token과 관련된 모든 보안 정책의 단일 진입점(Single Entry Point)으로, 다음 책임을 가집니다.
 *
 * <ul>
 *   <li>Refresh Token 원문(raw token)의 생성
 *   <li>저장소에 저장되기 전 해시(HMAC) 처리
 *   <li>TTL(만료 시간) 정책 적용
 *   <li>재사용 방지를 위한 토큰 회전(Rotation)
 *   <li>로그아웃 시 토큰 폐기(Revoke)
 * </ul>
 *
 * <p>이 클래스 외부에서는 절대 RefreshTokenStore에 직접 접근하지 않으며, raw refresh token 역시 이 클래스 외부로 유출되지 않도록
 * 설계되었습니다.
 *
 * <p>Infrastructure 레이어에 위치하지만, 단순 저장소가 아닌 <b>보안 정책과 흐름을 캡슐화</b>하는 역할을 수행합니다.
 */
@Component
@RequiredArgsConstructor
public class RefreshTokenManager {

  /** Refresh Token의 저장 및 원자적 회전을 담당하는 저장소 */
  private final RefreshTokenStore tokenStore;

  /** Raw Refresh Token을 단방향 해시(HMAC)로 변환하는 인코더 */
  private final RefreshTokenEncoder tokenEncoder;

  /** Refresh Token 원문을 생성하는 생성기(UUID 등) */
  private final RefreshTokenGenerator tokenGenerator;

  /** Refresh Token 만료 시간 및 보안 설정 값 */
  private final RefreshTokenProperties tokenProps;

  /**
   * 새 Refresh Token을 발급합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>Refresh Token 원문(raw token) 생성
   *   <li>저장 전 HMAC 해싱
   *   <li>TTL을 적용하여 저장소에 저장
   * </ol>
   *
   * <p>저장소에는 해시된 값만 저장되며, 클라이언트에는 raw refresh token만 반환됩니다.
   *
   * @param userId Refresh Token의 소유자 식별자
   * @return 발급된 Refresh Token 정보(raw token + 만료 시간)
   */
  public Mono<IssuedRefreshToken> issue(String userId) {
    String rawRefreshToken = tokenGenerator.generate();
    String hashedRefreshToken = tokenEncoder.encode(rawRefreshToken);
    Duration ttl = Duration.ofSeconds(tokenProps.getExpirationSeconds());

    return tokenStore
        .save(userId, hashedRefreshToken, ttl)
        .flatMap(
            saved -> {
              if (!saved) {
                // 저장 실패는 인증 시스템의 비정상 상태로 간주
                return Mono.error(new IllegalStateException("Failed to save refresh token"));
              }
              return Mono.just(
                  new IssuedRefreshToken(rawRefreshToken, tokenProps.getExpirationSeconds()));
            });
  }

  /**
   * Refresh Token을 재발급(회전)합니다.
   *
   * <p>이 메서드는 기존 Refresh Token의 유효성 검증과 새 Refresh Token 발급을 <b>원자적으로</b> 수행합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>기존 raw refresh token을 해싱
   *   <li>새 refresh token 생성 및 해싱
   *   <li>저장소에서 기존 토큰을 새 토큰으로 교체
   * </ol>
   *
   * <p>기존 토큰이 유효하지 않거나 이미 사용된 경우, 재사용 공격으로 판단하여 인증 오류를 반환합니다.
   *
   * @param oldRawRefreshToken 클라이언트가 보유한 기존 refresh token 원문
   * @return 회전된 Refresh Token 정보(userId + 새 raw token + 만료 시간)
   */
  public Mono<RotatedRefreshToken> rotate(String oldRawRefreshToken) {
    String oldHashedRefreshToken = tokenEncoder.encode(oldRawRefreshToken);

    String newRawRefreshToken = tokenGenerator.generate();
    String newHashedRefreshToken = tokenEncoder.encode(newRawRefreshToken);

    Duration ttl = Duration.ofSeconds(tokenProps.getExpirationSeconds());

    return tokenStore
        .rotate(oldHashedRefreshToken, newHashedRefreshToken, ttl)
        // 기존 토큰이 유효하지 않으면 인증 실패로 처리
        .switchIfEmpty(Mono.error(new UnauthorizedException("Invalid refresh token")))
        .map(
            userId ->
                new RotatedRefreshToken(
                    userId, newRawRefreshToken, tokenProps.getExpirationSeconds()));
  }

  /**
   * Refresh Token을 폐기합니다.
   *
   * <p>주로 로그아웃 시 호출되며, raw refresh token을 해싱한 뒤 저장소에서 삭제합니다.
   *
   * <p>이미 삭제되었거나 존재하지 않는 경우에도 별도 오류를 발생시키지 않고 정상 종료합니다.
   *
   * @param rawRefreshToken 클라이언트가 보유한 refresh token 원문
   * @return 처리 완료 신호
   */
  public Mono<Void> revoke(String rawRefreshToken) {
    String hashed = tokenEncoder.encode(rawRefreshToken);
    return tokenStore.delete(hashed).then();
  }
}
