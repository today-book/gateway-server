package org.todaybook.gateway.auth.domain;

public record JwtToken(String accessToken, String refreshToken, String tokenType, long expireIn) {}
