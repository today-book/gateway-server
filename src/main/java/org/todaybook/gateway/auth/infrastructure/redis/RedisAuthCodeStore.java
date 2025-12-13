package org.todaybook.gateway.auth.infrastructure.redis;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeConsumer;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeSaver;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class RedisAuthCodeStore implements AuthCodeSaver, AuthCodeConsumer {

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

  @Override
  public Mono<Boolean> save(String authCode, String kakaoId, Duration ttl) {
    return reactiveRedisTemplate.opsForValue().set(key(authCode), kakaoId, ttl);
  }

  @Override
  public Mono<String> getAndDeleteKakaoId(String authCode) {
    return reactiveRedisTemplate.opsForValue().getAndDelete(key(authCode));
  }

  private String key(String authCode) {
    return "auth:code:kakao:" + authCode;
  }
}
