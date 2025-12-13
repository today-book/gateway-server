package org.todaybook.gateway.auth.application.refresh;

public record RotatedRefreshToken(String userId, String token, long expiresInSeconds) {}
