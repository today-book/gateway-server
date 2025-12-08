package org.todaybook.gateway.security;

import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.todaybook.gateway.security.jwt.JwtProvider;
import org.todaybook.gateway.security.jwt.JwtTokenCreateCommand;
import org.todaybook.gateway.security.kakao.KakaoOAuthUser;
import reactor.core.publisher.Mono;

@Component
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

  private final AuthProperties authProperties;

  private final JwtProvider jwtProvider;

  @Override
  public Mono<Void> onAuthenticationSuccess(
      WebFilterExchange exchange, Authentication authentication) {
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

    KakaoOAuthUser user = KakaoOAuthUser.from(oAuth2User);

    String jwt =
        jwtProvider.createToken(new JwtTokenCreateCommand(user.kakaoId(), user.nickname()));

    return redirect(exchange, jwt);
  }

  private Mono<Void> redirect(WebFilterExchange exchange, String jwt) {

    URI redirectUri =
        UriComponentsBuilder.fromUriString(authProperties.getLoginSuccessRedirectUri())
            .queryParam("token", jwt)
            .build()
            .toUri();

    exchange.getExchange().getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getExchange().getResponse().getHeaders().setLocation(redirectUri);
    return exchange.getExchange().getResponse().setComplete();
  }
}
