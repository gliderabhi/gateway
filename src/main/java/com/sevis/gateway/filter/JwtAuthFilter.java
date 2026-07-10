package com.sevis.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secret;

    private static final List<String> PUBLIC_PATHS = List.of(
            "/user-service/api/auth/",
            "/kids-study-service/",
            "/songs-service/",
            "/photo-service/downloads/",
            "/listing-service/api/listings/photos/"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Let CORS preflight pass through before JWT validation
        if (exchange.getRequest().getMethod() == org.springframework.http.HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();

        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }
        if (isPublicListingRead(path, exchange.getRequest().getMethod())) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String token;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        } else {
            // Native <video>/<img> element loads and hls.js's manifest fetch don't go
            // through the app's HttpClient/interceptor, so they can't carry a custom
            // Authorization header — accept the same JWT via query param as a fallback
            // so authenticated media (thumbnails, HLS playlists, raw stream) can load.
            token = exchange.getRequest().getQueryParams().getFirst("access_token");
        }
        if (token == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Forward identity claims as headers so downstream services can use them
            // without parsing the JWT themselves
            ServerWebExchange mutated = exchange.mutate()
                    .request(r -> r.headers(headers -> {
                        headers.set("X-User-Id",      String.valueOf(claims.get("userId")));
                        headers.set("X-User-Role",    String.valueOf(claims.get("role")));
                        headers.set("X-Account-Type", String.valueOf(claims.get("accountType")));
                        Object dealerId = claims.get("dealerId");
                        if (dealerId != null) headers.set("X-Dealer-Id", String.valueOf(dealerId));
                    }))
                    .build();

            return chain.filter(mutated);
        } catch (JwtException | IllegalArgumentException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    // Browsing listings (search + viewing a single listing) is public — room
    // seekers shouldn't need an account just to look. "/mine" is deliberately
    // excluded since it requires the caller's own X-User-Id to scope results,
    // and every mutating endpoint (create/update/status/delete/media upload)
    // shares the same "/api/listings" path prefix, so this must also check
    // the HTTP method — a path-only bypass would make POST/PUT/DELETE public too.
    private static final String LISTINGS_PREFIX = "/listing-service/api/listings";

    private boolean isPublicListingRead(String path, HttpMethod method) {
        if (method != HttpMethod.GET) return false;
        if (!path.startsWith(LISTINGS_PREFIX)) return false;
        if (path.startsWith(LISTINGS_PREFIX + "/mine")) return false;
        return true;
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
