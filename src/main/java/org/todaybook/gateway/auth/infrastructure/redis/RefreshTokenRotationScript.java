package org.todaybook.gateway.auth.infrastructure.redis;

import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

@Component
public class RefreshTokenRotationScript {

  private final RedisScript<String> script;

  public RefreshTokenRotationScript() {
    this.script =
        RedisScript.of(new ClassPathResource("redis/refresh_token_rotate.lua"), String.class);
  }

  public RedisScript<String> get() {
    return script;
  }
}
