package org.todaybook.gateway.security.config;

import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.todaybook.gateway.security.oauth.OAuth2SuccessHandler;
import org.todaybook.gateway.security.publicapi.PublicApiPaths;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final OAuth2SuccessHandler successHandler;

  @Bean
  public SecurityWebFilterChain publicApiChain(ServerHttpSecurity http) {
    ServerWebExchangeMatcher publicMatcher =
        new OrServerWebExchangeMatcher(
            PublicApiPaths.PATHS.stream()
                .map(PathPatternParserServerWebExchangeMatcher::new)
                .collect(Collectors.toList()));

    return http.securityMatcher(publicMatcher)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .cors(Customizer.withDefaults())
        .authorizeExchange(ex -> ex.anyExchange().permitAll())
        .build();
  }

  @Bean
  public SecurityWebFilterChain securedChain(ServerHttpSecurity http) {

    return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
        .cors(Customizer.withDefaults())
        .authorizeExchange(
            exchange ->
                exchange
                    .pathMatchers("/oauth2/**", "/login/**", "/error")
                    .permitAll()
                    .anyExchange()
                    .authenticated())
        .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(successHandler))
        .build();
  }
}
