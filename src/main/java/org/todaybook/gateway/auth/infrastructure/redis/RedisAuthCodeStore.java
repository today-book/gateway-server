package org.todaybook.gateway.auth.infrastructure.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.todaybook.gateway.auth.application.exception.InternalServerErrorException;
import org.todaybook.gateway.auth.application.exception.UnauthorizedException;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeConsumer;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeSaver;
import org.todaybook.gateway.security.oauth.AuthCodePayload;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Redis 기반 AuthCode 저장소입니다.
 *
 * <h3>역할</h3>
 *
 * <ul>
 *   <li>OAuth 인증 과정에서 발급된 authCode ↔ AuthCodePayload를 Redis에 저장합니다.
 *   <li>authCode는 1회성으로 사용되며, 조회 시 즉시 삭제(getAndDelete)됩니다.
 * </ul>
 *
 * <h3>설계 포인트</h3>
 *
 * <ul>
 *   <li>Redis 접근은 ReactiveRedisTemplate을 사용하여 non-blocking으로 처리합니다.
 *   <li>Jackson 직렬화/역직렬화는 동기 작업이므로 boundedElastic 스케줄러에서 실행합니다.
 *   <li>authCode가 없거나 유효하지 않은 경우는 인증 실패(Unauthorized)로 처리합니다.
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class RedisAuthCodeStore implements AuthCodeSaver, AuthCodeConsumer {

  /** Redis key prefix (authCode 충돌 방지용 네임스페이스) */
  private static final String KEY_PREFIX = "auth:code:";

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
  private final ObjectMapper objectMapper;

  /**
   * authCode와 OAuth payload를 Redis에 저장합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>authCode 공백/무효 여부 검증
   *   <li>payload를 JSON으로 직렬화 (Jackson 동기 작업이므로 boundedElastic 스케줄러에서 실행)
   *   <li>Redis에 key-value 형태로 저장 (TTL 포함)
   * </ol>
   *
   * @param authCode 1회성 인증 코드
   * @param payload OAuth 인증 결과(provider, providerUserId 등)
   * @param ttl authCode 유효 시간
   * @return Redis 저장 성공 여부
   */
  @Override
  public Mono<Boolean> save(String authCode, AuthCodePayload payload, Duration ttl) {
    if (isBlank(authCode)) {
      return Mono.error(new UnauthorizedException("Invalid authCode"));
    }

    return Mono.fromCallable(() -> objectMapper.writeValueAsString(payload))
        .subscribeOn(Schedulers.boundedElastic())
        .onErrorMap(
            e -> new InternalServerErrorException("Failed to serialize authCode payload", e))
        .flatMap(json -> reactiveRedisTemplate.opsForValue().set(key(authCode), json, ttl));
  }

  /**
   * authCode에 해당하는 payload를 조회하고 즉시 삭제합니다.
   *
   * <p>처리 흐름:
   *
   * <ol>
   *   <li>authCode 공백/무효 여부 검증
   *   <li>Redis에서 getAndDelete 수행 (1회성 사용 보장)
   *   <li>값이 없으면 이미 사용되었거나 만료된 것으로 간주 → Unauthorized
   *   <li>JSON을 AuthCodePayload로 역직렬화 (Jackson 동기 작업이므로 boundedElastic 스케줄러에서 실행)
   * </ol>
   *
   * @param authCode 1회성 인증 코드
   * @return OAuth 인증 payload
   */
  @Override
  public Mono<AuthCodePayload> getAndDeletePayload(String authCode) {
    if (isBlank(authCode)) {
      return Mono.error(new UnauthorizedException("AuthCode is empty"));
    }

    return reactiveRedisTemplate
        .opsForValue()
        .getAndDelete(key(authCode))
        .switchIfEmpty(Mono.error(new UnauthorizedException("AuthCode not found or already used")))
        .flatMap(
            json ->
                Mono.fromCallable(() -> objectMapper.readValue(json, AuthCodePayload.class))
                    .subscribeOn(Schedulers.boundedElastic())
                    .onErrorMap(
                        e -> new InternalServerErrorException("AuthCode payload parse failed", e)));
  }

  /** Redis key 생성 (prefix + authCode) */
  private String key(String authCode) {
    return KEY_PREFIX + authCode;
  }

  /** 공백/빈 문자열 여부 체크 */
  private boolean isBlank(String value) {
    return !StringUtils.hasText(value);
  }
}
