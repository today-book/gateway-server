package org.todaybook.gateway.security.config;

import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.todaybook.gateway.security.exception.CustomAuthenticationEntryPoint;
import org.todaybook.gateway.security.oauth.OAuth2SuccessHandler;
import org.todaybook.gateway.security.publicapi.PublicApiPaths;

/**
 * Gateway Security 설정.
 *
 * <p>요청 성격에 따라 SecurityWebFilterChain을 분리하여 인증 방식과 응답 형태를 명확히 구분한다.
 *
 * <ul>
 *   <li>Public API: 인증 없이 접근 가능
 *   <li>OAuth Endpoint: 로그인/리다이렉션 전용
 *   <li>API Endpoint: JWT 기반 인증 필수
 * </ul>
 *
 * <p>각 체인은 {@link Order}로 우선순위를 가지며, 가장 먼저 매칭되는 체인만 적용된다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final OAuth2SuccessHandler successHandler;
  private final CustomAuthenticationEntryPoint authenticationEntryPoint;

  /** 인증이 필요 없는 Public API 체인. */
  @Bean
  @Order(1)
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

  /**
   * OAuth2 로그인 및 리다이렉션 전용 체인.
   *
   * <p>OAuth 인증 과정 중에는 JWT 인증을 요구하지 않으며, 인증 성공 시 {@link OAuth2SuccessHandler}에서 후처리를 수행한다.
   */
  @Bean
  @Order(2)
  public SecurityWebFilterChain oauthChain(ServerHttpSecurity http) {

    ServerWebExchangeMatcher oauthMatcher =
        new OrServerWebExchangeMatcher(
            new PathPatternParserServerWebExchangeMatcher("/oauth2/**"),
            new PathPatternParserServerWebExchangeMatcher("/login/**"));

    return http.securityMatcher(oauthMatcher)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(ex -> ex.anyExchange().permitAll())
        .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(successHandler))
        .build();
  }

  /**
   * JWT 기반 보호 API 체인.
   *
   * <p>모든 요청은 인증이 필요하며, 인증 실패 시 JSON 형태의 401/403 응답을 반환한다.
   */
  @Bean
  @Order(3)
  public SecurityWebFilterChain apiChain(ServerHttpSecurity http) {

    ServerWebExchangeMatcher apiMatcher =
        new OrServerWebExchangeMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"));

    return http.securityMatcher(apiMatcher)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .cors(Customizer.withDefaults())
        .authorizeExchange(ex -> ex.anyExchange().authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2
                    .jwt(Customizer.withDefaults())
                    .authenticationEntryPoint(authenticationEntryPoint))
        .build();
  }
}
