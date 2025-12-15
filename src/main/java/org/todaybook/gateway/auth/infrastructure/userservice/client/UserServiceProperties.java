package org.todaybook.gateway.auth.infrastructure.userservice.client;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "user-service")
public record UserServiceProperties(String baseUrl, String internalPath) {}
