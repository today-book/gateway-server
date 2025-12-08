package org.todaybook.gateway.security.cors;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "cors")
public class CorsProperties {

  /** 허용할 Origin 목록. */
  private List<String> allowedOrigins;
}
