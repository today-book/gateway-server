package org.todaybook.gateway.auth.infrastructure.refresh;

import java.util.UUID;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.refresh.RefreshTokenGenerator;

@Component
public class UUIDRefreshTokenGenerator implements RefreshTokenGenerator {
  public String generate() {
    return UUID.randomUUID().toString();
  }
}
