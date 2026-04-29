package com.ezmeal.gateway.filter;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtHeaderRelayFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(auth -> {
                    // JwtAuthenticationToken일 때만 실행
                    Jwt jwt = auth.getToken();

                    String userId = jwt.getSubject();
                    String email = jwt.getClaimAsString("email");

                    String roles = extractRoles(jwt);

                    ServerHttpRequest mutatedRequest = exchange.getRequest()
                            .mutate()
                            .headers(headers -> {
                                // Preventing HTTP Header Injection
                                headers.remove("X-User-Id");
                                headers.remove("X-User-Roles");
                                headers.remove("X-User-Email");

                                headers.set("X-User-Id", userId);
                                if(email != null) headers.set("X-User-Email", email);
                                if(roles != null && !roles.isBlank()) headers.set("X-User-Roles", roles);
                            })
                            .build();

                    return exchange.mutate()
                            .request(mutatedRequest)
                            .build();
                })
                // 타입이 다르거나 principal 이 없는 경우, 원본 요청 사용
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    // Extract Roles from Keycloak
    private String extractRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if(realmAccess == null) return "";

        Object rolesObj =  realmAccess.get("roles");

        if (!(rolesObj instanceof Collection<?> roles)) return "";

        return roles.stream()
                .map(Object::toString)
                .collect(Collectors.joining(","));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
