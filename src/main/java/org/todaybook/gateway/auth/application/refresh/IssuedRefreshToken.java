package org.todaybook.gateway.auth.application.refresh;

public record IssuedRefreshToken(String token, long expiresInSeconds) {}
