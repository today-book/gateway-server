package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.exception.InternalServerErrorException;
import org.todaybook.gateway.auth.application.spi.refresh.RefreshTokenStore;
import reactor.core.publisher.Mono;

/**
 * Redis 기반 Refresh Token 저장소입니다.
 *
 * <h3>역할</h3>
 *
 * <ul>
 *   <li>refresh token ↔ id 매핑을 Redis에 저장합니다.
 *   <li>refresh token 회전(rotate)을 Lua 스크립트로 원자적으로 수행합니다.
 * </ul>
 *
 * <h3>설계 포인트</h3>
 *
 * <ul>
 *   <li>refresh token은 서버 상태(stateful)로 관리하여 재사용 공격을 방지합니다.
 *   <li>rotate 동작은 Lua 스크립트를 사용해 (기존 토큰 조회 → 삭제 → 신규 토큰 저장)을 단일 Redis 연산으로 보장합니다.
 *   <li>TTL은 refresh token의 유효 기간을 의미합니다.
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class RedisRefreshTokenStore implements RefreshTokenStore {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
  private final RefreshTokenRotationScript rotationScript;

  /**
   * refresh token과 userId를 Redis에 저장합니다.
   *
   * <h3>처리 흐름</h3>
   *
   * <ul>
   *   <li>refresh token을 key로 사용합니다.
   *   <li>userId를 value로 Redis에 저장합니다.
   *   <li>TTL을 함께 설정하여 만료를 자동 처리합니다.
   * </ul>
   *
   * @param refreshToken 새로 발급된 refresh token (raw 값)
   * @param userId 인증된 사용자 식별자
   * @param ttl refresh token 유효 시간
   * @return Redis 저장 성공 여부
   */
  @Override
  public Mono<Boolean> save(String refreshToken, String userId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(refreshToken), userId, ttl);
  }

  /**
   * refresh token을 Redis에서 삭제합니다.
   *
   * <h3>동작 특성</h3>
   *
   * <ul>
   *   <li>존재하지 않는 토큰에 대해서도 false를 반환합니다.
   *   <li>로그아웃 시 idempotent 하게 사용될 수 있습니다.
   * </ul>
   *
   * @param refreshToken 삭제할 refresh token
   * @return 실제 삭제 여부
   */
  @Override
  public Mono<Boolean> delete(String refreshToken) {
    return reactiveRedisTemplate.delete(key(refreshToken)).map(deletedCount -> deletedCount > 0);
  }

  /**
   * refresh token을 회전(rotation)합니다.
   *
   * <h3>처리 흐름</h3>
   *
   * <ol>
   *   <li>기존 refresh token으로 userId를 조회합니다.
   *   <li>기존 refresh token을 삭제합니다.
   *   <li>새 refresh token으로 동일 userId를 저장합니다 (TTL 포함).
   *   <li>userId를 반환합니다.
   * </ol>
   *
   * <h3>보안적 의미</h3>
   *
   * <ul>
   *   <li>모든 과정은 Lua 스크립트로 단일 Redis 연산에서 수행됩니다.
   *   <li>refresh token 재사용(replay) 공격을 방지합니다.
   * </ul>
   *
   * @param oldRefreshToken 기존 refresh token
   * @param newRefreshToken 새로 발급할 refresh token
   * @param ttl 새 refresh token 유효 시간
   * @return 성공 시 id, 기존 토큰이 유효하지 않으면 empty
   */
  @Override
  public Mono<String> rotate(String oldRefreshToken, String newRefreshToken, Duration ttl) {
    long seconds = ttl.getSeconds();
    if (seconds <= 0) {
      return Mono.error(new InternalServerErrorException("Invalid refresh token ttl"));
    }

    String oldKey = key(oldRefreshToken);
    String newKey = key(newRefreshToken);

    return reactiveRedisTemplate
        .execute(rotationScript.get(), List.of(oldKey, newKey), String.valueOf(seconds))
        .next();
  }

  /**
   * Redis에 저장될 refresh token key를 생성합니다.
   *
   * @param refreshToken raw refresh token
   * @return Redis key (prefix 포함)
   */
  private String key(String refreshToken) {
    return "auth:refresh:" + refreshToken;
  }
}
