package org.todaybook.gateway.auth.infrastructure.userservice.model;

public record OauthIdentity(OauthProvider provider, String providerUserId) {}
