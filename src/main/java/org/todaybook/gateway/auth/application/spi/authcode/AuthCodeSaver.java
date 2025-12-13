package org.todaybook.gateway.auth.application.spi.authcode;

import java.time.Duration;
import reactor.core.publisher.Mono;

/**
 * OAuth 인증 과정에서 발급된 authCode를 저장하기 위한 SPI입니다.
 *
 * <p>이 인터페이스는 Application 레이어가 authCode의 실제 저장소 구현(Redis, DB 등)을 알지 못하도록 하기 위한 저장 계약(Storage
 * Contract)을 정의합니다.
 *
 * <p>authCode는 <b>일회성(one-time)</b> 인증 수단이므로, 반드시 만료 시간(TTL)을 함께 저장해야 합니다.
 *
 * <p>저장소 구현체는 다음 요구사항을 충족해야 합니다.
 *
 * <ul>
 *   <li>authCode는 TTL 만료 후 자동으로 제거되어야 합니다.
 *   <li>동일한 authCode가 중복 저장되지 않도록 보장하는 것이 바람직합니다.
 * </ul>
 *
 * <p>에러 처리 정책:
 *
 * <ul>
 *   <li>저장 성공 여부는 {@code Boolean}으로 반환합니다.
 *   <li>저장 실패 시 예외를 던질지 여부는 구현체 정책에 따릅니다.
 * </ul>
 *
 * @see reactor.core.publisher.Mono
 */
public interface AuthCodeSaver {

  /**
   * authCode와 사용자 식별자를 TTL과 함께 저장합니다.
   *
   * @param authCode OAuth 인증 이후 발급된 일회성 인증 코드
   * @param kakaoId authCode와 매핑될 사용자 식별자
   * @param ttl authCode의 유효 기간
   * @return 저장 성공 여부를 나타내는 {@code Mono<Boolean>}
   */
  Mono<Boolean> save(String authCode, String kakaoId, Duration ttl);
}
