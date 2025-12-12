package org.todaybook.gateway.ratelimiter;

import java.util.Objects;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {

  @Bean
  public KeyResolver searchKeyResolver() {
    return exchange -> {
      String clientIP =
          Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
              .getAddress()
              .getHostAddress();

      return Mono.just(clientIP);
    };
  }
}
