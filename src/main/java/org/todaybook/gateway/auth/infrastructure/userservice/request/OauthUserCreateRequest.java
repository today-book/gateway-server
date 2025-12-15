package org.todaybook.gateway.auth.infrastructure.userservice.request;

import org.todaybook.gateway.auth.infrastructure.userservice.model.OauthProvider;

public interface OauthUserCreateRequest {
  OauthProvider provider();
}
