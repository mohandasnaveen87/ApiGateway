package com.example.api_gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity // Crucial: This tells Spring to use Reactive Security
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF for your stateless setup
            .authorizeExchange(exchanges -> exchanges
                // 1. Let login and registration requests pass straight through to AUTH-SERVICE
                .pathMatchers("/auth/login", "/auth/register").permitAll()
                
                // 2. Everything else (cards, accounts, etc.) requires a valid JWT token
                .anyExchange().authenticated()
            )
            // 3. Turn on JWT Validation using the jwk-set-uri specified in application.properties
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
            
        return http.build();
    }
}