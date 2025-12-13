package org.todaybook.gateway.auth.presentation.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(@NotBlank String authCode) {}
