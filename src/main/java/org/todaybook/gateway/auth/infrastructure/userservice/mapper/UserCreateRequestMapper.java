package org.todaybook.gateway.auth.infrastructure.userservice.mapper;

import org.todaybook.gateway.auth.infrastructure.userservice.model.OauthIdentity;
import org.todaybook.gateway.auth.infrastructure.userservice.request.KakaoUserCreateRequest;
import org.todaybook.gateway.auth.infrastructure.userservice.request.OauthUserCreateRequest;

public final class UserCreateRequestMapper {
  private UserCreateRequestMapper() {}

  public static OauthUserCreateRequest toRequest(OauthIdentity identity, String nickname) {
    return switch (identity.provider()) {
      case KAKAO -> new KakaoUserCreateRequest(identity.providerUserId(), nickname);
      default -> throw new IllegalArgumentException("Unsupported provider: " + identity.provider());
    };
  }
}
