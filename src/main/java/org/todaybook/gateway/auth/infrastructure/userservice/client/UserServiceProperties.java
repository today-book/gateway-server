package org.todaybook.gateway.auth.infrastructure.userservice.client;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "user-service")
public record UserServiceProperties(
    @NotBlank(message = "user-service.baseUrl must not be blank") String baseUrl,
    @NotBlank(message = "user-service.internalPath must not be blank")
        @Pattern(regexp = "^/.*", message = "user-service.internalPath must start with '/'")
        String internalPath) {}
