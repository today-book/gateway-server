package org.todaybook.gateway.security.jwt;

public record JwtToken(String accessToken, String refreshToken, String tokenType, long expireIn) {}
