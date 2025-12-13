package org.todaybook.gateway.auth.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.todaybook.gateway.auth.application.AuthService;
import org.todaybook.gateway.security.jwt.JwtToken;
import reactor.core.publisher.Mono;

@RequestMapping("/api/v1/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/logout")
  public Mono<Void> logout(@RequestHeader("X-Refresh-Token") String refreshToken) {
    return authService.delete(refreshToken);
  }

  @PostMapping("/refresh")
  public Mono<JwtToken> refresh(@RequestHeader("X-Refresh-Token") String refreshToken) {
    return authService.refresh(refreshToken);
  }
}
