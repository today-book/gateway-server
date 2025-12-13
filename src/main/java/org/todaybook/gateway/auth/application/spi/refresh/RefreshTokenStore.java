package org.todaybook.gateway.auth.application.spi.refresh;

import java.time.Duration;
import reactor.core.publisher.Mono;

/**
 * Refresh Token의 저장, 폐기, 회전을 담당하는 SPI(Storage Contract)입니다.
 *
 * <p>이 인터페이스는 Application 레이어가 Refresh Token의 실제 저장소 구현(Redis, DB 등)을 알지 못하도록 하기 위한 저장소 경계 역할을 합니다.
 *
 * <p>Refresh Token은 장기 권한을 부여하는 민감한 인증 수단이므로, 저장소 구현체는 보안과 원자성(atomicity)을 최우선으로 고려해야 합니다.
 *
 * <p>주요 설계 원칙:
 *
 * <ul>
 *   <li>저장되는 Refresh Token은 반드시 인코딩된 값이어야 합니다.
 *   <li>원본(raw) Refresh Token은 절대로 저장되지 않습니다.
 *   <li>회전(rotation)은 재사용 공격을 방지하기 위해 원자적으로 수행되어야 합니다.
 * </ul>
 *
 * <p>에러 및 반환 값 정책:
 *
 * <ul>
 *   <li>존재하지 않는 토큰에 대한 요청은 예외를 발생시키지 않고, {@code false} 또는 {@code Mono.empty()}로 표현합니다.
 *   <li>존재 여부 판단 및 인증 오류 처리는 Application 레이어의 책임입니다.
 * </ul>
 */
public interface RefreshTokenStore {

  /**
   * 인코딩된 Refresh Token을 사용자 식별자와 함께 저장합니다.
   *
   * @param refreshToken 인코딩된 Refresh Token
   * @param userId Refresh Token과 매핑될 사용자 식별자
   * @param ttl Refresh Token의 유효 기간
   * @return 저장 성공 여부를 나타내는 {@code Mono<Boolean>}
   */
  Mono<Boolean> save(String refreshToken, String userId, Duration ttl);

  /**
   * 인코딩된 Refresh Token을 저장소에서 삭제합니다.
   *
   * <p>이미 삭제되었거나 존재하지 않는 경우에도 {@code false}를 반환하며 예외를 발생시키지 않습니다.
   *
   * @param refreshToken 인코딩된 Refresh Token
   * @return 삭제 성공 여부를 나타내는 {@code Mono<Boolean>}
   */
  Mono<Boolean> delete(String refreshToken);

  /**
   * Refresh Token을 회전(rotation)합니다.
   *
   * <p>이 메서드는 다음 동작을 <b>원자적</b>으로 수행해야 합니다.
   *
   * <ol>
   *   <li>기존 Refresh Token의 존재 여부 확인
   *   <li>기존 Refresh Token 제거
   *   <li>새로운 Refresh Token 저장 및 TTL 갱신
   * </ol>
   *
   * <p>회전에 성공한 경우, 기존 Refresh Token에 매핑된 사용자 식별자를 반환합니다. 존재하지 않거나 이미 소비된 토큰인 경우 {@code
   * Mono.empty()}를 반환합니다.
   *
   * @param oldRefreshToken 기존 인코딩된 Refresh Token
   * @param newRefreshToken 새로 발급된 인코딩된 Refresh Token
   * @param ttl 새 Refresh Token의 유효 기간
   * @return 사용자 식별자(userId)를 담은 {@code Mono}, 회전에 실패한 경우 {@code Mono.empty()}
   */
  Mono<String> rotate(String oldRefreshToken, String newRefreshToken, Duration ttl);
}
