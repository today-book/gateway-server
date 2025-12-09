package org.todaybook.gateway.security.jwt;

import java.util.List;

public record JwtTokenCreateCommand(String kakaoId, String nickname, List<String> roles) {}
