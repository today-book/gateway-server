package org.todaybook.gateway.auth.application.spi.token;

import org.todaybook.gateway.auth.application.token.AccessTokenIssueCommand;
import org.todaybook.gateway.auth.application.token.IssuedAccessToken;

/**
 * Access Token 발급을 담당하는 SPI(Service Provider Interface)입니다.
 *
 * <p>이 인터페이스는 Application 레이어가 Access Token의 실제 발급 방식(JWT, Opaque Token 등)과 구체적인 기술 구현을 알지 않도록 하기
 * 위한 추상화 경계입니다.
 *
 * <p>Application 레이어는 이 SPI를 통해
 *
 * <ul>
 *   <li>"어떤 정보로 Access Token을 발급할 것인가"
 *   <li>"발급 결과로 무엇을 반환받는가"
 * </ul>
 *
 * 에만 관심을 가지며, 토큰 포맷, 서명 알고리즘, 키 관리 방식 등은 Infrastructure 구현에 위임합니다.
 *
 * <p>구현체는 다음 책임을 가집니다.
 *
 * <ul>
 *   <li>Access Token 생성 및 서명
 *   <li>만료 시간 계산
 *   <li>발급 결과를 {@link IssuedAccessToken}으로 반환
 * </ul>
 *
 * <p>이 SPI를 도입함으로써, Access Token 발급 전략(JWT ↔ 다른 포맷)의 변경이 Application 레이어에 영향을 주지 않도록 보장합니다.
 */
public interface AccessTokenIssuer {

  /**
   * 주어진 발급 정보(Command)를 기반으로 Access Token을 발급합니다.
   *
   * @param command Access Token 발급에 필요한 사용자 식별자 및 Claim 정보
   * @return 발급된 Access Token과 만료 정보를 담은 {@link IssuedAccessToken}
   */
  IssuedAccessToken issue(AccessTokenIssueCommand command);
}
