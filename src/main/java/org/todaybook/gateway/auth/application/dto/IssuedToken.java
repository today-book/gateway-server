package org.todaybook.gateway.auth.application.dto;

public record IssuedToken(
    String accessToken, String refreshToken, String tokenType, long expireIn) {}
