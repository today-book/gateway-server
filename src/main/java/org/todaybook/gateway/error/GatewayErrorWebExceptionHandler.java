package org.todaybook.gateway.error;

import io.netty.channel.ConnectTimeoutException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.cloud.gateway.support.TimeoutException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.codec.DecodingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.reactive.function.server.*;
import org.springframework.web.server.MethodNotAllowedException;
import org.springframework.web.server.MissingRequestValueException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.UnsupportedMediaTypeStatusException;
import reactor.core.publisher.Mono;

/**
 * Gateway 전역 에러 핸들러.
 *
 * <p>Gateway는 시스템의 경계(boundary) 역할을 수행하므로, 비즈니스 에러가 아닌 인증/인가, 요청 유효성, 라우팅, 트래픽, 다운스트림 장애만을 이 계층에서
 * 처리합니다.
 *
 * <p>모든 예외는 {@link GatewayErrorCode}로 정규화되며, 클라이언트에는 에러 코드만 전달되고 상세 원인은 로그로만 남깁니다.
 *
 * @author 김지원
 * @since 1.0.0.
 */
@Slf4j
@Configuration
@Order(-2)
public class GatewayErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

  public GatewayErrorWebExceptionHandler(
      ErrorAttributes errorAttributes,
      WebProperties webProperties,
      ApplicationContext applicationContext,
      ServerCodecConfigurer serverCodecConfigurer) {

    super(errorAttributes, webProperties.getResources(), applicationContext);
    setMessageWriters(serverCodecConfigurer.getWriters());
    setMessageReaders(serverCodecConfigurer.getReaders());
  }

  /** 모든 요청에 대해 본 에러 핸들러를 적용합니다. */
  @Override
  protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {

    return RouterFunctions.route(RequestPredicates.all(), this::render);
  }

  /** 예외를 {@link GatewayErrorCode}로 변환하고 표준 JSON 에러 응답을 생성합니다. */
  private Mono<ServerResponse> render(ServerRequest request) {
    Throwable error = getError(request);
    GatewayErrorCode errorCode = resolve(error);

    logByLevel(errorCode, error, request);

    return ServerResponse.status(errorCode.status())
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(GatewayErrorResponse.of(errorCode.name()));
  }

  /**
   * 발생한 예외를 Gateway 레벨 에러 코드로 매핑합니다.
   *
   * <p>우선순위:
   *
   * <ol>
   *   <li>Gateway 정책 예외
   *   <li>다운스트림 장애
   *   <li>요청 유효성 문제
   *   <li>HTTP 상태 기반 예외
   *   <li>Security 예외
   * </ol>
   */
  private GatewayErrorCode resolve(Throwable error) {

    if (error instanceof ServiceException ge) {
      return ge.getErrorCode();
    }

    if (error instanceof TimeoutException) {
      return GatewayErrorCode.GATEWAY_TIMEOUT;
    }

    if (error instanceof ConnectTimeoutException) {
      return GatewayErrorCode.SERVICE_UNAVAILABLE;
    }

    if (error instanceof MissingRequestValueException) {
      return GatewayErrorCode.MISSING_REQUEST_VALUE;
    }

    if (error instanceof WebExchangeBindException || error instanceof DecodingException) {
      return GatewayErrorCode.REQUEST_BIND_ERROR;
    }

    if (error instanceof UnsupportedMediaTypeStatusException) {
      return GatewayErrorCode.UNSUPPORTED_MEDIA_TYPE;
    }

    if (error instanceof MethodNotAllowedException) {
      return GatewayErrorCode.METHOD_NOT_ALLOWED;
    }

    if (error instanceof ResponseStatusException rse) {
      if (rse.getStatusCode() == HttpStatus.TOO_MANY_REQUESTS) {
        return GatewayErrorCode.RATE_LIMIT_EXCEEDED;
      }
      if (rse.getStatusCode() == HttpStatus.NOT_FOUND) {
        return GatewayErrorCode.NOT_FOUND;
      }
      if (rse.getStatusCode() == HttpStatus.UNAUTHORIZED) {
        return GatewayErrorCode.UNAUTHORIZED;
      }
      if (rse.getStatusCode() == HttpStatus.FORBIDDEN) {
        return GatewayErrorCode.FORBIDDEN;
      }
    }

    if (error instanceof AuthenticationException) {
      return GatewayErrorCode.UNAUTHORIZED;
    }

    if (error instanceof AccessDeniedException) {
      return GatewayErrorCode.FORBIDDEN;
    }

    return GatewayErrorCode.INTERNAL_ERROR;
  }

  /**
   * 에러 코드에 따라 로그 레벨을 다르게 기록합니다.
   *
   * <ul>
   *   <li>장애 계열: error (stacktrace 포함)
   *   <li>정책/요청 오류: warn 또는 info
   * </ul>
   */
  private void logByLevel(GatewayErrorCode errorCode, Throwable error, ServerRequest request) {
    String path = request.path();
    String method = request.method().name();

    switch (errorCode) {
      case SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, INTERNAL_ERROR ->
          log.error(
              "[GatewayError] code={} {} {} cause={}",
              errorCode,
              method,
              path,
              error.getClass().getSimpleName(),
              error);

      case RATE_LIMIT_EXCEEDED -> log.info("[GatewayError] code={} {} {}", errorCode, method, path);

      default ->
          log.warn(
              "[GatewayError] code={} {} {} cause={}",
              errorCode,
              method,
              path,
              error.getClass().getSimpleName());
    }
  }
}
