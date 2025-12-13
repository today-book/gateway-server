package org.todaybook.gateway.security.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.domain.TokenSerializationException;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtProvider;
import org.todaybook.gateway.auth.domain.JwtToken;
import org.todaybook.gateway.auth.Infrastructure.jwt.JwtTokenCreateCommand;
import org.todaybook.gateway.security.kakao.KakaoOAuth2User;
import reactor.core.publisher.Mono;

@Component
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

  private final JwtProvider jwtProvider;

  private final ObjectMapper objectMapper;

  @Override
  public Mono<Void> onAuthenticationSuccess(
      WebFilterExchange exchange, Authentication authentication) {
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

    KakaoOAuth2User user = KakaoOAuth2User.from(oAuth2User);

    JwtTokenCreateCommand command =
        new JwtTokenCreateCommand(user.kakaoId(), user.nickname(), List.of("USER_ROLE"));

    return jwtProvider.createToken(command).flatMap(jwt -> writeTokenResponse(exchange, jwt));
  }

  private Mono<Void> writeTokenResponse(WebFilterExchange exchange, JwtToken jwt) {
    var response = exchange.getExchange().getResponse();
    response.setStatusCode(HttpStatus.OK);
    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

    return Mono.fromCallable(() -> objectMapper.writeValueAsBytes(jwt))
        .flatMap(bytes -> response.writeWith(Mono.just(response.bufferFactory().wrap(bytes))))
        .onErrorMap(
            JsonProcessingException.class,
            e -> new TokenSerializationException("JSON_SERIALIZATION_ERROR", e));
  }
}
