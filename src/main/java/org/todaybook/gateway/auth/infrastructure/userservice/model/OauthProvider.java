package org.todaybook.gateway.auth.infrastructure.userservice.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OauthProvider {
  KAKAO("kakao");

  private final String path;

  public static OauthProvider from(String raw) {
    if (raw == null || raw.isBlank()) {
      throw new IllegalArgumentException("provider is blank");
    }

    return switch (raw.trim().toLowerCase()) {
      case "kakao" -> KAKAO;
      default -> throw new IllegalArgumentException("Unknown provider: " + raw);
    };
  }
}
