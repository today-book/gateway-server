package org.todaybook.gateway.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.auth")
@Data
public class AuthProperties {

  /** OAuth 로그인 성공 후 프론트엔드 redirect URI. */
  private String loginSuccessRedirectUri;
}
