package com.ezmeal.gateway.config;

import com.ezmeal.gateway.exception.SecurityErrorResponseWriter;
import com.ezmeal.gateway.exception.code.ErrorCode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import lombok.RequiredArgsConstructor;
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

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityErrorResponseWriter writer;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        // 전역 인증 제외
                        .pathMatchers(
                                "/realms/easymeal/protocol/openid-connect/token",
                                "/realms/easymeal/protocol/openid-connect/certs",
                                "/realms/easymeal/.well-known/openid-configuration",
                                "/api/v1/users/signup/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()
                        // 특정 api 인증 제외 -------------------------
                        // product
                        .pathMatchers(HttpMethod.GET, "/api/v1/products/**").permitAll()
                        // review
                        .pathMatchers(HttpMethod.GET, "/api/v1/reviews/myReviews/**").hasAnyRole("ADMIN", "USER")
                        .pathMatchers(HttpMethod.GET, "/api/v1/reviews/**").permitAll()
                        // company
                        .pathMatchers(HttpMethod.GET, "/api/v1/companies/**").permitAll()
                        // 권한 강제 ----------------------------------
                        .pathMatchers(HttpMethod.DELETE, "/api/v1/notifications/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.POST, "/api/v1/notifications/**").hasRole("ADMIN")
                        // test시에 사용하는 uri
                        .pathMatchers("/api/v1/test/anonymous").permitAll()
                        .pathMatchers("/api/v1/test/user").authenticated()
                        .pathMatchers("/api/v1/test/admin").hasRole("ADMIN")
                        // 그 외 모두 인증 요구 -------------------------
                        .anyExchange().authenticated()
                )
                // JWT 검증(Keycloak에 위임)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                // handling exception
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((exchange, ex) -> writer.writeErrorResponse(exchange, ErrorCode.UNAUTHORIZED))
                        .accessDeniedHandler((exchange, denied) -> writer.writeErrorResponse(exchange, ErrorCode.FORBIDDEN))
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

            if(realmAccess!=null){
                Object rolesObj =  realmAccess.get("roles");

                if(rolesObj instanceof Collection<?> roles) {
                    roles.forEach(role ->
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toString()))
                    );
                }
            }

            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }
}
