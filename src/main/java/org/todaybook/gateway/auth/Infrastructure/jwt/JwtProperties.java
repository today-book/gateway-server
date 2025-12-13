package org.todaybook.gateway.auth.Infrastructure.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

  private String secret;
  private Long accessTokenExpirationSeconds;
  private Long refreshTokenExpirationSeconds;
}
