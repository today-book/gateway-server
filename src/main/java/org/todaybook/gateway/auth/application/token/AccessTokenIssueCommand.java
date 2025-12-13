package org.todaybook.gateway.auth.application.token;

import java.util.List;

public record AccessTokenIssueCommand(String userId, String nickname, List<String> roles) {}
