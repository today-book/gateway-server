package org.todaybook.gateway.security.cors;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "cors")
public class CorsProperties {

  /** 허용할 Origin 목록. */
  private List<String> allowedOrigins;
}
