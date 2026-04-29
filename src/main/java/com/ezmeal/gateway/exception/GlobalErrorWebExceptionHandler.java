package com.ezmeal.gateway.exception;

import com.ezmeal.gateway.exception.code.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(-2)
@RequiredArgsConstructor
public class GlobalErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    private final SecurityErrorResponseWriter writer;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        log.error("Unhandled gateway exception", ex);

        // 이미 응답이 나간경우, 상위로 위임
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }

        return writer.writeErrorResponse(exchange, ErrorCode.INTERNAL_ERROR);
    }
}
