package org.todaybook.gateway.security.jwt;

public record JwtTokenCreateCommand(String kakaoId, String nickname) {}
