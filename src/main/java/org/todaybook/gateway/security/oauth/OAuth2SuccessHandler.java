package org.todaybook.gateway.security.oauth;

import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.todaybook.gateway.auth.application.spi.authcode.AuthCodeSaver;
import org.todaybook.gateway.security.kakao.KakaoOAuth2User;
import reactor.core.publisher.Mono;

/**
 * OAuth2 로그인 성공 시 호출되어 authCode를 발급하고 프론트엔드로 리다이렉트하는 WebFlux 전용 인증 성공 핸들러입니다.
 *
 * <p>이 클래스는 OAuth2 인증 성공 이후 세션을 사용하지 않고, 일회성 인증 코드(authCode)를 발급하여 프론트엔드가 자체 로그인
 * API(/api/v1/auth/login)를 호출하도록 유도합니다.
 *
 * @author 김지원
 * @since 1.0.0
 */
@Component
@EnableConfigurationProperties(AuthProperties.class)
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

  /** OAuth 로그인 이후 발급된 authCode를 Redis에 저장하는 스토어 */
  private final AuthCodeSaver authCodeSaver;

  /** OAuth 관련 설정 값 (로그인 성공 리다이렉트 URI 등) */
  private final AuthProperties authProperties;

  /**
   * OAuth2 인증 성공 시 호출되는 메서드입니다.
   *
   * <p>인증이 성공하면 다음 순서로 처리됩니다.
   *
   * <ol>
   *   <li>Authentication 객체에서 Kakao 사용자 정보 추출
   *   <li>일회성 인증 코드(authCode) 생성
   *   <li>authCode ↔ kakaoId 매핑 정보를 Redis에 저장
   *   <li>authCode를 포함하여 프론트엔드로 리다이렉트
   * </ol>
   *
   * @param exchange WebFilterExchange (요청/응답 컨텍스트)
   * @param authentication 인증 성공 후 Authentication 객체
   * @return 응답 완료를 나타내는 Mono
   */
  @Override
  public Mono<Void> onAuthenticationSuccess(
      WebFilterExchange exchange, Authentication authentication) {

    // OAuth2 인증 Principal을 Kakao 도메인 사용자로 변환
    KakaoOAuth2User user = extractKakaoUser(authentication);

    // 일회성 인증 코드(authCode) 생성
    String authCode = generateAuthCode();

    // authCode 저장 후 프론트엔드로 리다이렉트
    return saveAuthCode(authCode, user)
        .flatMap(
            saved ->
                saved
                    ? redirectWithAuthCode(exchange, authCode)
                    : Mono.error(new IllegalStateException("Failed to store authCode")));
  }

  /**
   * Authentication 객체에서 OAuth2User를 추출한 뒤 KakaoOAuth2User 도메인 모델로 변환합니다.
   *
   * @param authentication 인증 성공 정보
   * @return KakaoOAuth2User 도메인 객체
   */
  private KakaoOAuth2User extractKakaoUser(Authentication authentication) {
    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
    return KakaoOAuth2User.from(oAuth2User);
  }

  /**
   * UUID 기반의 일회성 인증 코드(authCode)를 생성합니다.
   *
   * <p>해당 authCode는 Redis에 저장되며, 이후 로그인 API 호출 시 단 한 번만 사용됩니다.
   *
   * @return 생성된 authCode 문자열
   */
  private String generateAuthCode() {
    return UUID.randomUUID().toString();
  }

  /**
   * authCode와 Kakao 사용자 정보를 Redis에 저장합니다.
   *
   * <p>authCode는 짧은 TTL(60초)을 가지며, 로그인 API에서 token / token 발급 시 검증에 사용됩니다.
   *
   * @param authCode 생성된 인증 코드
   * @param user Kakao OAuth 사용자 정보
   * @return 저장 성공 여부를 나타내는 Mono
   */
  private Mono<Boolean> saveAuthCode(String authCode, KakaoOAuth2User user) {
    return authCodeSaver.save(
        authCode,
        new AuthCodePayload("kakao", user.kakaoId(), user.nickname()),
        Duration.ofSeconds(60));
  }

  /**
   * 로그인 성공 후 authCode를 쿼리 파라미터로 포함하여 프론트엔드 로그인 성공 페이지로 리다이렉트합니다.
   *
   * @param exchange WebFilterExchange
   * @param authCode 발급된 인증 코드
   * @return 리다이렉트 응답 완료 Mono
   */
  private Mono<Void> redirectWithAuthCode(WebFilterExchange exchange, String authCode) {
    return Mono.defer(
        () -> {
          var response = exchange.getExchange().getResponse();
          response.setStatusCode(HttpStatus.FOUND);
          response
              .getHeaders()
              .setLocation(
                  UriComponentsBuilder.fromUriString(authProperties.getLoginSuccessRedirectUri())
                      .queryParam("authCode", authCode)
                      .build()
                      .toUri());
          return response.setComplete();
        });
  }
}
