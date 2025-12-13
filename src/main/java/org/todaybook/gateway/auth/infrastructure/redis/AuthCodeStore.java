package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthCodeStore {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

  public Mono<Boolean> save(String authCode, String kakaoId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(authCode), kakaoId, ttl);
  }

  public Mono<String> getKakaoId(String authCode) {
    return reactiveRedisTemplate.opsForValue().get(key(authCode));
  }

  public Mono<Long> delete(String authCode) {
    return reactiveRedisTemplate.delete(key(authCode));
  }

  private String key(String authCode) {
    return "auth:code:kakao:" + authCode;
  }
}
