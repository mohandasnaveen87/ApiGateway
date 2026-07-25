package com.example.api_gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity // Crucial: This tells Spring to use Reactive Security
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF for your stateless setup
            .authorizeExchange(exchanges -> exchanges
                // 1. Let login and registration requests pass straight through to AUTH-SERVICE
               // .pathMatchers("/auth/login", "/auth/register").permitAll()
            		// .pathMatchers("/auth/login", "/auth/register").permitAll()
                // 2. Everything else (cards, accounts, etc.) requires a valid JWT token
            		.pathMatchers("/auth/login").permitAll()
                    
                    // 2. Restrict registration so ONLY authenticated users with ROLE_CHILD can access it
                    .pathMatchers("/auth/register").hasRole("CHILD")
            		.anyExchange().authenticated()
            )
            // 3. Turn on JWT Validation using the jwk-set-uri specified in application.properties
           // .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
            .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor()))
                );
        return http.build();
    }
    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("scope"); // Or "roles"
        authoritiesConverter.setAuthorityPrefix("ROLE_");     // Maps "PARENT" -> "ROLE_PARENT"

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }
}