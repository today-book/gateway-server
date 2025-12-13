package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class RefreshTokenStore {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
  private final RefreshTokenRotationScript rotationScript;

  public Mono<Boolean> save(String refreshToken, String userId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(refreshToken), userId, ttl);
  }

  public Mono<Long> delete(String refreshToken) {
    return reactiveRedisTemplate.delete(key(refreshToken));
  }

  public Mono<String> rotate(
      String oldRefreshToken, String newRefreshToken, Duration ttl) {

    String oldKey = key(oldRefreshToken);
    String newKey = key(newRefreshToken);

    return reactiveRedisTemplate
        .execute(
            rotationScript.get(),
            List.of(oldKey, newKey),
            String.valueOf(ttl.getSeconds())
        )
        .next(); // Lua 결과는 Flux로 오므로 단건 추출
  }

  private String key(String refreshToken) {
    return "auth:refresh:" + refreshToken;
  }
}
