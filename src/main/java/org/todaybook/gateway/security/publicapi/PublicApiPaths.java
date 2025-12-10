package org.todaybook.gateway.security.publicapi;

import java.util.List;

public final class PublicApiPaths {
  public static final List<String> PATHS = List.of("/api/v1/search/books", "/public/**");
}
