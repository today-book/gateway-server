package org.todaybook.gateway.auth.presentation.dto;

import org.todaybook.gateway.auth.application.dto.IssuedToken;

public record JwtToken(String accessToken, String tokenType, long expiresIn) {
  public static JwtToken from(IssuedToken issuedToken) {
    return new JwtToken(issuedToken.accessToken(), issuedToken.tokenType(), issuedToken.expireIn());
  }
}
