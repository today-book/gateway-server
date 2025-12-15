package org.todaybook.gateway.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.todaybook.gateway.auth.application.dto.AuthenticatedUser;
import org.todaybook.gateway.auth.application.exception.InternalServerErrorException;
import org.todaybook.gateway.auth.application.exception.UnauthorizedException;
import org.todaybook.gateway.auth.infrastructure.userservice.client.UserServiceClient;
import org.todaybook.gateway.auth.infrastructure.userservice.mapper.UserCreateRequestMapper;
import org.todaybook.gateway.auth.infrastructure.userservice.model.OauthIdentity;
import org.todaybook.gateway.auth.infrastructure.userservice.model.OauthProvider;
import org.todaybook.gateway.security.oauth.AuthCodePayload;
import reactor.core.publisher.Mono;

/**
 * Auth 플로우에서 "유저 식별/생성"을 담당하는 Application Service입니다.
 *
 * <p>역할:
 *
 * <ul>
 *   <li>OAuth 인증 후 받은 payload(provider/providerUserId)를 이용해 유저를 조회합니다.
 *   <li>유저가 없다면(User service 404 → Mono.empty()) 회원가입을 시도합니다.
 *   <li>최종적으로 토큰 발급에 필요한 형태({@link AuthenticatedUser})로 변환하여 반환합니다.
 * </ul>
 *
 * <p>중요:
 *
 * <ul>
 *   <li>실제 회원가입 정책(기본 Role 부여 등)은 User 서비스의 책임입니다.
 *   <li>이 클래스는 "조회 → 없으면 가입" 오케스트레이션만 수행합니다.
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class UserIdentityService {

  private final UserServiceClient userServiceClient;

  /**
   * OAuth 인증 이후 전달받은 payload를 기반으로 유저를 조회하거나, 존재하지 않으면 생성합니다.
   *
   * <p><b>호출 시점 전제(Why):</b>
   *
   * <ul>
   *   <li>이 메서드는 OAuth 인증이 정상적으로 완료된 이후에만 호출됩니다.
   *   <li>따라서 payload 자체가 null이거나 provider/providerUserId가 비어 있는 경우는 클라이언트 오류가 아닌 서버 내부 상태 불일치(버그)로
   *       간주합니다.
   * </ul>
   *
   * <p><b>처리 흐름:</b>
   *
   * <ol>
   *   <li>OAuth identity(provider + providerUserId) 파싱 및 검증
   *   <li>User 서비스에 해당 identity로 유저 조회
   *   <li>존재하지 않으면 회원가입 요청(idempotent)
   *   <li>UserSummary를 인증 컨텍스트용 {@link AuthenticatedUser}로 변환
   * </ol>
   */
  public Mono<AuthenticatedUser> resolveOrCreateFromOauth(AuthCodePayload payload) {
    if (payload == null) {
      return Mono.error(new InternalServerErrorException("AuthCodePayload is null"));
    }
    if (isBlank(payload.provider()) || isBlank(payload.providerUserId())) {
      return Mono.error(
          new InternalServerErrorException(
              "Invalid OAuth payload: provider/providerUserId is blank"));
    }

    OauthIdentity identity = toIdentity(payload);

    return userServiceClient
        .findByOauth(identity.provider().getPath(), identity.providerUserId())
        .map(AuthenticatedUser::from)
        .switchIfEmpty(
            userServiceClient
                .createOauthUser(UserCreateRequestMapper.toRequest(identity, payload.nickname()))
                .map(AuthenticatedUser::from));
  }

  /**
   * userId로 유저를 조회하여 {@link AuthenticatedUser}로 변환합니다.
   *
   * <p>주로 refresh 플로우에서 rotate 결과의 userId로 최신 roles/status/nickname을 반영하기 위해 사용됩니다.
   *
   * <p>User 서비스에서 404가 내려오면(= Mono.empty()) 인증 불가로 보는 것이 일반적이므로, empty를 그대로 흘리지 않고 Unauthorized로
   * 변환합니다.
   */
  public Mono<AuthenticatedUser> loadAuthenticatedUser(String userId) {
    if (isBlank(userId)) {
      return Mono.error(new InternalServerErrorException("id is blank"));
    }

    return userServiceClient
        .findByUserId(userId)
        .switchIfEmpty(Mono.error(new UnauthorizedException("USER_NOT_FOUND")))
        .map(AuthenticatedUser::from);
  }

  /**
   * 문자열이 실제 의미 있는 텍스트를 가지고 있는지 여부를 판단합니다.
   *
   * <p>OAuth payload 및 userId 검증 시, null/blank 처리 규칙을 한 곳에 고정하기 위해 분리했습니다.
   */
  private boolean isBlank(String value) {
    return !StringUtils.hasText(value);
  }

  /**
   * OAuth payload로부터 {@link OauthIdentity}를 생성합니다.
   *
   * <p><b>Why:</b>
   *
   * <ul>
   *   <li>provider 문자열을 enum으로 변환하는 책임을 한 곳에 모으기 위함입니다.
   *   <li>잘못된 provider 값은 외부 입력 오류이지만, 이 메서드가 호출되는 시점에서는 이미 인증이 완료된 상태이므로 서버 내부 상태 불일치로 간주하여 500 계열
   *       예외로 변환합니다.
   * </ul>
   *
   * <p>이 메서드에서 발생한 예외는 Reactive 체인에서 자동으로 error signal로 전파됩니다.
   */
  private OauthIdentity toIdentity(AuthCodePayload payload) {
    try {
      return new OauthIdentity(OauthProvider.from(payload.provider()), payload.providerUserId());
    } catch (IllegalArgumentException e) {
      throw new InternalServerErrorException("Invalid OAuth payload: " + e.getMessage(), e);
    }
  }
}
