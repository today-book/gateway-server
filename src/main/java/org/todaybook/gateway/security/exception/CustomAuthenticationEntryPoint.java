package org.todaybook.gateway.security.exception;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.todaybook.gateway.error.GatewayErrorCode;
import org.todaybook.gateway.error.GatewayException;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

    log.warn(
        "[Security] Unauthorized access {} {}",
        exchange.getRequest().getMethod(),
        exchange.getRequest().getURI());

    return Mono.error(new GatewayException(GatewayErrorCode.UNAUTHORIZED));
  }
}
