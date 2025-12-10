package org.todaybook.gateway.security.publicapi;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

@Component
public class PublicApiMatcher {

  private final PathMatcher pathMatcher = new AntPathMatcher();

  public boolean isPublic(ServerHttpRequest request) {
    String path = request.getPath().value();
    return PublicApiPaths.PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
  }
}
