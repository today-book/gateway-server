package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.spi.refresh.RefreshTokenStore;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class RedisRefreshTokenStore implements RefreshTokenStore {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
  private final RefreshTokenRotationScript rotationScript;

  @Override
  public Mono<Boolean> save(String refreshToken, String userId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(refreshToken), userId, ttl);
  }

  @Override
  public Mono<Boolean> delete(String refreshToken) {
    return reactiveRedisTemplate.delete(key(refreshToken)).map(deletedCount -> deletedCount > 0);
  }

  @Override
  public Mono<String> rotate(String oldRefreshToken, String newRefreshToken, Duration ttl) {

    String oldKey = key(oldRefreshToken);
    String newKey = key(newRefreshToken);

    return reactiveRedisTemplate
        .execute(rotationScript.get(), List.of(oldKey, newKey), String.valueOf(ttl.getSeconds()))
        .next(); // Lua 결과는 Flux로 오므로 단건 추출
  }

  private String key(String refreshToken) {
    return "auth:refresh:" + refreshToken;
  }
}
