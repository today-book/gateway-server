package org.todaybook.gateway.security.publicapi;

import java.util.List;

public final class PublicApiPaths {
  public static final List<String> PATHS =
      List.of(
          "/public/**",
          "/api/v1/search/books",
          "/api/v1/auth/**");
}
