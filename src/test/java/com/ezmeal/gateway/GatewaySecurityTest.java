package com.ezmeal.gateway;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import reactor.core.publisher.Mono;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class GatewaySecurityTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void 익명사용자는_permitAll인_API에_접근할_수_있다() {
        webTestClient.get()
                .uri("/api/v1/test/anonymous")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void 익명사용자는_인증이_필요한_API에_접근하면_401을_반환한다() {
        webTestClient.get()
                .uri("/api/v1/test/user")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void 토큰이_없으면_401을_반환한다() {
        webTestClient.get()
                .uri("/api/v1/test/user")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void 잘못된_토큰이면_401을_반환한다() {
        given(reactiveJwtDecoder.decode(anyString()))
                .willReturn(Mono.error(new BadJwtException("Invalid token")));

        webTestClient.get()
                .uri("/api/v1/test/user")
                .header("Authorization", "Bearer invalid-token")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void USER권한은_USER_API에_접근할_수_있다() {
        given(reactiveJwtDecoder.decode("user-token"))
                .willReturn(Mono.just(jwtWithRoles("USER")));

        webTestClient.get()
                .uri("/api/v1/test/user")
                .header("Authorization", "Bearer user-token")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void USER는_ADMIN_API에_접근하면_403을_반환한다() {
        given(reactiveJwtDecoder.decode("user-token"))
                .willReturn(Mono.just(jwtWithRoles("USER")));

        webTestClient.get()
                .uri("/api/v1/test/admin")
                .header("Authorization", "Bearer user-token")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void ADMIN은_ADMIN_API에_접근할_수_있다() {
        given(reactiveJwtDecoder.decode("admin-token"))
                .willReturn(Mono.just(jwtWithRoles("ADMIN")));

        webTestClient.get()
                .uri("/api/v1/test/admin")
                .header("Authorization", "Bearer admin-token")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void ADMIN은_USER_API에도_접근할_수_있다() {
        given(reactiveJwtDecoder.decode("admin-token"))
                .willReturn(Mono.just(jwtWithRoles("ADMIN")));

        webTestClient.get()
                .uri("/api/v1/test/user")
                .header("Authorization", "Bearer admin-token")
                .exchange()
                .expectStatus().isOk();
    }

    private Jwt jwtWithRoles(String... roles) {
        return Jwt.withTokenValue(String.join("-", roles).toLowerCase() + "-token")
                .header("alg", "none")
                .subject("test-user-id")
                .issuer("http://localhost:8080/realms/easymeal")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claim("realm_access", Map.of(
                        "roles", List.of(roles)
                ))
                .build();
    }

    @TestConfiguration
    static class TestRouteConfig {

        @Bean
        RouterFunction<ServerResponse> testRoutes() {
            return route(GET("/api/v1/test/user"),
                    request -> ServerResponse.ok().bodyValue("user ok"))
                    .andRoute(GET("/api/v1/test/admin"),
                            request -> ServerResponse.ok().bodyValue("admin ok"))
                    .andRoute(GET("/api/v1/test/anonymous"),
                            request -> ServerResponse.ok().bodyValue("anonymous ok"));
        }
    }
}
