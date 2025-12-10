package org.todaybook.gateway.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "app.auth")
public class AuthProperties {

  /** OAuth 로그인 성공 후 프론트엔드 redirect URI. */
  private String loginSuccessRedirectUri;
}
