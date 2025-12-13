package org.todaybook.gateway.auth.application.token;

public record IssuedAccessToken(String token, long expiresInSeconds) {}
