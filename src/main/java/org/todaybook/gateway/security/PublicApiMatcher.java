package org.todaybook.gateway.security;

import java.util.List;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

@Component
public class PublicApiMatcher {

  private static final List<String> PUBLIC_PATHS = List.of("/api/v1/search/books", "/public/**");

  private final PathMatcher pathMatcher = new AntPathMatcher();

  public boolean isPublic(ServerHttpRequest request) {
    String path = request.getPath().value();
    return PUBLIC_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
  }
}
