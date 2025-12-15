package org.todaybook.gateway.auth.application.spi.authcode;

import org.todaybook.gateway.security.oauth.AuthCodePayload;
import reactor.core.publisher.Mono;

/**
 * OAuth 인증 과정에서 발급된 authCode를 소비(consumption)하기 위한 SPI입니다.
 *
 * <p>이 인터페이스는 Application 레이어가 authCode의 실제 저장 방식(Redis, DB 등)을 알지 못하도록 하기 위한 경계 역할을 합니다.
 *
 * <p>구현체는 authCode를 조회함과 동시에 즉시 삭제해야 하며, 이를 통해 authCode의 <b>1회성 사용(one-time use)</b>을 보장해야 합니다.
 *
 * <p>주요 보장 사항:
 *
 * <ul>
 *   <li>authCode는 한 번만 소비 가능해야 합니다.
 *   <li>이미 소비되었거나 존재하지 않는 경우 값을 반환하지 않습니다.
 * </ul>
 *
 * <p>에러 처리 정책:
 *
 * <ul>
 *   <li>authCode가 존재하지 않는 경우 {@code Mono.empty()}를 반환합니다.
 *   <li>존재 여부 판단은 Application 레이어에서 수행합니다.
 * </ul>
 *
 * @see reactor.core.publisher.Mono
 */
public interface AuthCodeConsumer {

  /**
   * authCode를 조회하고 즉시 소비(삭제)하여 사용자 식별자를 반환합니다.
   *
   * <p>이 메서드는 반드시 <b>원자적(atomic)</b>으로 동작해야 하며, 조회와 삭제 사이에 다른 요청이 끼어들 수 없어야 합니다.
   *
   * @param authCode OAuth 인증 이후 발급된 일회성 인증 코드
   * @return 사용자 식별자(kakaoId)를 담은 Mono, authCode가 존재하지 않거나 이미 소비된 경우 {@code Mono.empty()}
   */
  Mono<AuthCodePayload> getAndDeletePayload(String authCode);
}
