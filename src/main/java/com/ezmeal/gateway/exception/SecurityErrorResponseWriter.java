package com.ezmeal.gateway.exception;

import com.ezmeal.gateway.exception.code.ErrorCode;
import com.ezmeal.gateway.exception.response.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public Mono<Void> writeErrorResponse(ServerWebExchange exchange, ErrorCode errorCode) {
        ServerHttpResponse response = exchange.getResponse();

        // 응답 작성 시작시, 다시 같은 응답 작성하지 않도록 방어
        if (response.isCommitted()) {
            return Mono.empty();
        }

        response.setStatusCode(errorCode.getStatus());
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ApiResponse<Void> body = ApiResponse.error(errorCode);

        return Mono.fromCallable(() -> objectMapper.writeValueAsBytes(body))
                .map(bytes -> response.bufferFactory().wrap(bytes))
                .flatMap(buffer -> response.writeWith(Mono.just(buffer)));
    }
}
