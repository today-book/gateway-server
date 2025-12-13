package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class RefreshTokenStore {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

  public Mono<Boolean> save(String refreshToken, String userId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(refreshToken), userId, ttl);
  }

  public Mono<String> findUserId(String refreshToken) {
    return reactiveRedisTemplate.opsForValue().get(key(refreshToken));
  }

  public Mono<Long> delete(String refreshToken) {
    return reactiveRedisTemplate.delete(key(refreshToken));
  }

  private String key(String refreshToken) {
    return "auth:refresh:" + refreshToken;
  }
}
