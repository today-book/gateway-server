package org.todaybook.gateway.security.kakao;

import java.util.Map;
import org.springframework.security.oauth2.core.user.OAuth2User;

public record KakaoOAuth2User(String kakaoId, String nickname) {

  public static KakaoOAuth2User from(OAuth2User oAuth2User) {
    Map<String, Object> attributes = oAuth2User.getAttributes();

    String kakaoId = extractKakaoId(attributes);
    String nickname = extractNickname(attributes);

    return new KakaoOAuth2User(kakaoId, nickname);
  }

  @SuppressWarnings("unchecked")
  private static String extractNickname(Map<String, Object> attributes) {
    String nickname = "Unknown";
    Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");

    if (kakaoAccount != null) {
      Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

      if (profile != null && profile.get("nickname") != null) {
        nickname = profile.get("nickname").toString();
      }
    }
    return nickname;
  }

  private static String extractKakaoId(Map<String, Object> attributes) {
    Object idObj = attributes.get("id");
    if (idObj == null) {
      throw new IllegalArgumentException("Kakao OAuth user id is missing");
    }
    return String.valueOf(idObj);
  }
}
