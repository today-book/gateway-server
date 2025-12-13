package org.todaybook.gateway.auth.application.spi;

import reactor.core.publisher.Mono;

public interface AuthCodeConsumer {

  /** authCode를 조회하고 즉시 소비합니다. - 존재하지 않으면 Mono.empty() */
  Mono<String> getAndDeleteKakaoId(String authCode);
}
