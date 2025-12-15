package org.todaybook.gateway.auth.infrastructure.userservice.client;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.todaybook.gateway.auth.application.exception.InternalServerErrorException;
import org.todaybook.gateway.auth.infrastructure.userservice.model.UserSummary;
import org.todaybook.gateway.auth.infrastructure.userservice.request.OauthUserCreateRequest;
import reactor.core.publisher.Mono;

/**
 * User 서비스와 통신하는 WebClient 어댑터입니다.
 *
 * <p>Auth/Gateway는 User 서비스의 내부 구현을 알 필요가 없으며, 이 클래스는 User 서비스 API 호출 및 HTTP 상태 코드 → Auth 애플리케이션
 * 예외로의 변환 책임만을 가집니다.
 *
 * <p>주요 설계 원칙:
 *
 * <ul>
 *   <li>404는 "존재하지 않음"으로 해석하여 Mono.empty()로 변환합니다.
 *   <li>그 외 오류는 User 서비스 장애 또는 계약 위반으로 간주하여 InternalServerErrorException으로 래핑합니다.
 *   <li>원인 분석을 위해 ClientResponseException을 cause로 보존합니다.
 * </ul>
 */
@Component
@EnableConfigurationProperties(UserServiceProperties.class)
public class UserServiceClient {

  private final WebClient webClient;

  public UserServiceClient(WebClient.Builder builder, UserServiceProperties userServiceProperties) {
    this.webClient =
        builder
            .baseUrl(userServiceProperties.baseUrl() + userServiceProperties.internalPath())
            .build();
  }

  /**
   * OAuth(provider + providerUserId) 기준으로 유저를 조회합니다.
   *
   * <p>존재하지 않는 경우(404)는 정상 흐름으로 간주하여 Mono.empty()를 반환합니다. 이는 "조회 후 없으면 가입" 패턴을 구현하기 위함입니다.
   *
   * @param provider OAuth 제공자(kakao, google 등)
   * @param providerUserId OAuth 제공자 내부 사용자 식별자
   * @return 조회된 유저 요약 정보 또는 empty
   */
  public Mono<UserSummary> findByOauth(String provider, String providerUserId) {
    return webClient
        .get()
        .uri("/{provider}/{providerUserId}", provider, providerUserId)
        .exchangeToMono(
            resp -> {
              if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                return Mono.empty();
              }
              if (resp.statusCode().is2xxSuccessful()) {
                return resp.bodyToMono(UserSummary.class);
              }
              return toUserServiceUnavailable(resp);
            });
  }

  /**
   * OAuth 사용자 회원가입을 요청합니다.
   *
   * <p>이 API는 idempotent 하게 동작하는 것을 전제로 하며, 이미 존재하는 사용자의 경우에도 200/201로 동일한 UserSummary를 반환합니다.
   *
   * <p>4xx 오류는 OAuth 가입 요청에 대한 User 서비스의 검증/계약 실패로 간주합니다.
   *
   * @param req OAuth 회원가입 요청 정보
   * @return 생성(또는 기존) 유저 요약 정보
   */
  public Mono<UserSummary> createOauthUser(OauthUserCreateRequest req) {

    return webClient
        .post()
        .uri("/{provider}", req.provider().getPath())
        .bodyValue(req)
        .exchangeToMono(
            resp -> {
              if (resp.statusCode().is2xxSuccessful()) {
                return resp.bodyToMono(UserSummary.class);
              }
              if (resp.statusCode().is4xxClientError()) {
                return toUserServiceRejected(resp);
              }
              return toUserServiceUnavailable(resp);
            });
  }

  /**
   * id 기준으로 유저를 조회합니다.
   *
   * <p>404는 호출부에서 정책적으로 판단할 수 있도록 Mono.empty()로 변환합니다. (예: 로그인 플로우에서는 비정상, 가입 플로우에서는 정상 처리 등)
   *
   * @param userId 내부 사용자 식별자
   * @return 조회된 유저 요약 정보 또는 empty
   */
  public Mono<UserSummary> findByUserId(String userId) {
    return webClient
        .get()
        .uri("/{userId}", userId)
        .exchangeToMono(
            resp -> {
              if (resp.statusCode() == HttpStatus.NOT_FOUND) {
                return Mono.empty();
              }
              if (resp.statusCode().is2xxSuccessful()) {
                return resp.bodyToMono(UserSummary.class);
              }
              return toUserServiceUnavailable(resp);
            });
  }

  /**
   * User 서비스 장애(5xx 등)를 Auth 애플리케이션 예외로 변환합니다.
   *
   * <p>원래의 ClientResponseException을 cause로 보존하여 운영 환경에서 원인 추적이 가능하도록 합니다.
   */
  private <T> Mono<T> toUserServiceUnavailable(ClientResponse resp) {
    return resp.createException()
        .flatMap(
            ex ->
                Mono.error(
                    new InternalServerErrorException(
                        "User service unavailable: " + resp.statusCode(), ex)));
  }

  /**
   * User 서비스가 OAuth 가입 요청을 거부한 경우(4xx)를 처리합니다.
   *
   * <p>클라이언트 잘못이라기보다는, 서비스 간 계약/검증 실패로 간주하여 InternalServerErrorException으로 래핑합니다.
   */
  private <T> Mono<T> toUserServiceRejected(ClientResponse resp) {
    return resp.createException()
        .flatMap(
            ex ->
                Mono.error(
                    new InternalServerErrorException(
                        "User service rejected oauth signup request: " + resp.statusCode(), ex)));
  }
}
