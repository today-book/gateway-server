package org.todaybook.gateway.auth.infrastructure.userservice.model;

import java.util.List;
import org.todaybook.gateway.auth.infrastructure.userservice.UserRole;

public record UserSummary(String id, Long kakaoId, String nickname, List<UserRole> roles) {}
