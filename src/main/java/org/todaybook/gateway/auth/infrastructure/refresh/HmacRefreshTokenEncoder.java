package org.todaybook.gateway.auth.infrastructure.refresh;

import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.todaybook.gateway.auth.application.spi.refresh.RefreshTokenEncoder;

/**
 * Refresh Token을 HMAC-SHA256 알고리즘으로 해싱하는 Encoder 구현체입니다.
 *
 * <p>이 클래스는 <b>Refresh Token 원문을 절대 저장하지 않기</b> 위한 보안 경계 역할을 합니다. 클라이언트로부터 전달받은 raw refresh token을
 * HMAC으로 해싱한 뒤, 저장소(Redis 등)에는 오직 해시 값만 저장하도록 강제합니다.
 *
 * <p>HMAC을 사용하는 이유:
 *
 * <ul>
 *   <li>단방향 해시이므로 원문 복원이 불가능합니다.
 *   <li>서버 비밀키(secret)를 알지 못하면 동일한 해시를 생성할 수 없습니다.
 *   <li>DB/Redis 유출 시에도 refresh token 탈취를 방지합니다.
 * </ul>
 *
 * <p>이 구현은 Infrastructure 레이어에 위치하며, 토큰 암호화 방식(HMAC, SHA, KMS 등)을 교체할 수 있도록 {@link
 * RefreshTokenEncoder} 인터페이스를 구현합니다.
 */
@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(RefreshTokenProperties.class)
public class HmacRefreshTokenEncoder implements RefreshTokenEncoder {

  /** HMAC 해싱에 사용할 알고리즘 (HmacSHA256) */
  private static final String HMAC_ALG = "HmacSHA256";

  /** refresh token 해싱에 사용할 비밀키 설정 값 */
  private final RefreshTokenProperties props;

  /**
   * HMAC 연산에 사용할 SecretKeySpec입니다.
   *
   * <p>{@link Mac} 객체는 thread-safe 하지 않으므로 공유하지 않고, 대신 SecretKeySpec만 초기화 시점에 생성해 재사용합니다.
   */
  private SecretKeySpec keySpec;

  /**
   * 애플리케이션 초기화 시 refresh token 해싱에 사용할 비밀키를 준비합니다.
   *
   * <p>설정 누락으로 인한 보안 사고를 방지하기 위해 secret 값이 비어 있는 경우 즉시 애플리케이션을 실패시킵니다.
   */
  @PostConstruct
  void init() {
    String secret = props.getSecret();

    if (secret == null || secret.isBlank()) {
      throw new IllegalStateException("refresh-token.secret must not be blank");
    }

    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

    // HmacSHA256은 최소 256bit(32byte) 이상 권장
    if (keyBytes.length < 32) {
      throw new IllegalStateException(
          "refresh-token.secret must be at least 32 bytes for HmacSHA256");
    }

    this.keySpec = new SecretKeySpec(keyBytes, HMAC_ALG);
  }

  /**
   * Raw Refresh Token을 HMAC-SHA256 방식으로 해싱합니다.
   *
   * <p>입력값은 클라이언트가 보유한 refresh token 원문이며, 반환값은 저장소에 저장되는 해시 값입니다.
   *
   * <p>Base64 URL-safe 인코딩을 사용하여 Redis key, URL, 로그 등에서 안전하게 사용할 수 있도록 합니다.
   *
   * @param refreshToken 클라이언트가 전달한 raw refresh token
   * @return HMAC으로 해싱된 refresh token 값
   */
  @Override
  public String encode(String refreshToken) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALG);
      mac.init(keySpec);

      byte[] hmac = mac.doFinal(refreshToken.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);

    } catch (Exception e) {
      // 해싱 실패는 곧 인증 시스템의 치명적 오류이므로 Runtime 예외로 즉시 전파합니다.
      throw new IllegalStateException("Refresh token HMAC failed", e);
    }
  }
}
