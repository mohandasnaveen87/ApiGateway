package com.example.api_gateway;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;

import reactor.core.publisher.Mono;
@Configuration
public class RateLimitConfig {

    /**
     * Resolves key by User ID (e.g., from JWT or HTTP Header).
     * Fallback to 'anonymous' if unauthenticated.
     */
	@Bean
    @Primary
    public KeyResolver userKeyResolver() {
        return exchange -> ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .filter(Authentication::isAuthenticated)
            .map(Authentication::getPrincipal)
            .cast(Jwt.class)
            .map(jwt -> jwt.getClaimAsString("sub")) // Change "sub" to "user_id" if your provider uses a custom claim
            .defaultIfEmpty("anonymous");
    }

    /**
     * Alternative: Resolves key by Client Remote IP Address.
     */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> Mono.just(
            exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
        );
    }
}