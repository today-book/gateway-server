package org.todaybook.gateway.security.kakao;

import java.util.Map;
import org.springframework.security.oauth2.core.user.OAuth2User;

@SuppressWarnings("unchecked")
public record KakaoOAuthUser(String kakaoId, String nickname) {

  public static KakaoOAuthUser from(OAuth2User oAuth2User) {
    Map<String, Object> attributes = oAuth2User.getAttributes();

    String kakaoId = String.valueOf(attributes.get("id"));

    String nickname = "Unknown";
    Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");

    if (kakaoAccount != null) {
      Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

      if (profile != null && profile.get("nickname") != null) {
        nickname = profile.get("nickname").toString();
      }
    }

    return new KakaoOAuthUser(kakaoId, nickname);
  }
}
