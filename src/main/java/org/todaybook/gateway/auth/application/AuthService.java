package org.todaybook.gateway.auth.application;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.todaybook.gateway.auth.Infrastructure.redis.RefreshTokenStore;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtProvider;
import org.todaybook.gateway.auth.domain.JwtToken;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtTokenCreateCommand;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final RefreshTokenStore refreshTokenStore;
  private final JwtProvider jwtProvider;

  public Mono<JwtToken> refresh(String refreshToken) {
    return refreshTokenStore
        .findUserId(refreshToken)
        .switchIfEmpty(Mono.error(new UnauthorizedException()))
        .flatMap(
            userId ->
                refreshTokenStore
                    .delete(refreshToken)
                    .then(
                        jwtProvider.createToken(new JwtTokenCreateCommand(userId, "", List.of()))));
  }

  public Mono<Void> delete(String refreshToken) {
    return refreshTokenStore.delete(refreshToken).then();
  }
}
