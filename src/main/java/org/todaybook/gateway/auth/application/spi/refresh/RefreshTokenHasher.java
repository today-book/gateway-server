package org.todaybook.gateway.auth.application.spi.refresh;

/**
 * Refresh Token을 안전하게 변환(해싱)하기 위한 SPI입니다.
 *
 * <p>이 인터페이스는 Application 레이어가 Refresh Token의 실제 보호 방식(HMAC, Hash, 암호화 등)을 알지 못하도록 하기 위한 보안 경계 역할을
 * 합니다.
 *
 * <p>인코딩된 Refresh Token은 저장소(Redis, DB 등)에 저장되며, 원본(raw) Refresh Token은 절대로 저장되어서는 안 됩니다.
 *
 * <p>구현체는 다음 요구사항을 충족해야 합니다.
 *
 * <ul>
 *   <li>동일한 입력 Refresh Token에 대해 항상 동일한 결과를 반환해야 합니다.
 *   <li>출력 값으로부터 원본 Refresh Token을 복원할 수 없어야 합니다.
 *   <li>충분한 보안 강도를 보장해야 합니다.
 * </ul>
 *
 * <p>이 SPI를 통해 Application 레이어는 "Refresh Token을 어떻게 보호하는지"가 아닌 "Refresh Token을 안전하게 비교/저장할 수 있다"는
 * 사실에만 의존합니다.
 */
public interface RefreshTokenHasher {

  /**
   * 원본(raw) Refresh Token을 안전하게 해싱하여 반환합니다.
   *
   * <p>반환되는 값은 저장 및 비교 용도로만 사용되며, 클라이언트로 노출되어서는 안 됩니다.
   *
   * @param refreshToken 클라이언트가 보유한 원본 Refresh Token
   * @return 인코딩된 Refresh Token
   */
  String hash(String refreshToken);
}
