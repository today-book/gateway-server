package org.todaybook.gateway.auth.application.token;

import java.util.List;
import org.todaybook.gateway.auth.infrastructure.userservice.UserRole;

public record AccessTokenIssueCommand(String userId, String nickname, List<UserRole> roles) {}
