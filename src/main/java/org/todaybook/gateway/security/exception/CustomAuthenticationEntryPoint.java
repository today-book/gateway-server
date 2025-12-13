package org.todaybook.gateway.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.todaybook.commoncore.error.ErrorResponse;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

    log.error("Authentication failed", ex);

    HttpStatus unauthorized = HttpStatus.UNAUTHORIZED;
    ErrorResponse<Void> errorResponse =
        ErrorResponse.of(unauthorized.name(), "인증되지 않은 사용자입니다. 로그인 후 다시 시도해주세요.");

    byte[] body;
    try {
      body = objectMapper.writeValueAsBytes(errorResponse);
    } catch (Exception e) {
      body = "{}".getBytes(StandardCharsets.UTF_8);
    }

    exchange.getResponse().setStatusCode(unauthorized);
    exchange
        .getResponse()
        .getHeaders()
        .setContentType(org.springframework.http.MediaType.APPLICATION_JSON);

    return exchange
        .getResponse()
        .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
  }
}
