package org.todaybook.gateway.security.oauth;

public record AuthCodePayload(String provider, String providerUserId, String nickname) {}
