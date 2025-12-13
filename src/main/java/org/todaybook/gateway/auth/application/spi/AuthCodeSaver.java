package org.todaybook.gateway.auth.application.spi;

import java.time.Duration;
import reactor.core.publisher.Mono;

public interface AuthCodeSaver {

  Mono<Boolean> save(String authCode, String kakaoId, Duration ttl);
}
