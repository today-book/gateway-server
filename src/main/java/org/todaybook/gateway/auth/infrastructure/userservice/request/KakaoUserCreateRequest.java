package org.todaybook.gateway.auth.infrastructure.userservice.request;

import org.todaybook.gateway.auth.infrastructure.userservice.model.OauthProvider;

public record KakaoUserCreateRequest(String kakaoId, String nickname)
    implements OauthUserCreateRequest {

  @Override
  public OauthProvider provider() {
    return OauthProvider.KAKAO;
  }
}
