package com.ezmeal.gateway.config;

import com.ezmeal.gateway.exception.SecurityErrorResponseWriter;
import com.ezmeal.gateway.exception.code.ErrorCode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityErrorResponseWriter writer;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)

            .authorizeExchange(exchange -> exchange
                // 접근 차단
                .pathMatchers(
                    "/internal/**"
                ).denyAll()
                // NOTE: swagger는 관리자 도구로 가정합니다.
                .pathMatchers(
                    "/swagger-ui/**",
                    "/v3/api-docs/**"
                ).hasRole("ADMIN")
                // 전역 인증 제외
                .pathMatchers(
                    "/api/v1/users/signin",
                    "/api/v1/users/signup",
                    "/actuator/health",
                    "/actuator/prometheus",
                    "/actuator/info"
                ).permitAll()
                // PG사로부터의 응답 수신을 위한 인증 제외 api
                .pathMatchers(
                    HttpMethod.POST,"/api/v1/payments/confirm"
                ).permitAll()
                // 특정 도메인의 일부 api에 대한 인증 제외
                .pathMatchers(HttpMethod.GET, "/api/v1/products").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/v1/companies").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/v1/reviews").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/v1/reviews/*").permitAll()
                // test시에 사용하는 api
                .pathMatchers("/api/v1/test/anonymous").permitAll()
                .pathMatchers("/api/v1/test/user").authenticated()
                .pathMatchers("/api/v1/test/admin").hasRole("ADMIN")
                // 그 외 모두 인증 요구
                .anyExchange().authenticated()
            )
            // JWT 검증(Keycloak에 위임)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            // handling exception
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((exchange, ex) -> {
                    log.warn(
                        "Gateway authentication failed. method={}, path={}, message={}",
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getURI().getPath(),
                        ex.getMessage(),
                        ex
                    );
                    return writer.writeErrorResponse(exchange, ErrorCode.UNAUTHORIZED);
                })
                .accessDeniedHandler((exchange, denied) -> {
                    log.warn(
                        "Gateway access denied. method={}, path={}, message={}",
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getURI().getPath(),
                        denied.getMessage(),
                        denied
                    );
                    return writer.writeErrorResponse(exchange, ErrorCode.FORBIDDEN);
                })
            )
            .build();
    }

    /**
     * Keycloak Role을 {@code hasRole()}에서 사용하기 위한 Converter
     */
    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {

        return jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            Map<String, Object> realmAccess = jwt.getClaim("realm_access");

            if (realmAccess != null) {
                Object rolesObj = realmAccess.get("roles");

                if (rolesObj instanceof Collection<?> roles) {
                    roles.forEach(role ->
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toString()))
                    );
                }
            }

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }
}
