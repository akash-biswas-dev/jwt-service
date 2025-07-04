package com.cromxt.authentication.webflux;

import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.cromxt.authentication.JwtService;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class ReactiveJwtAuthenticationFilter implements WebFilter {

    private final JwtService jwtService;
    private final String location;

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        Mono<SecurityContext> securityContext = ReactiveSecurityContextHolder.getContext();

        return securityContext
                .switchIfEmpty(Mono.just(new SecurityContextImpl()))
                .flatMap(context -> {
                    if(context.getAuthentication() != null) {
                        return chain.filter(exchange);
                    }
                    return verifyToken(exchange, chain);
                });

    }

    private Mono<Void> verifyToken(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        String authHeader = request.getHeaders().getFirst("Authorization");

        if (Objects.nonNull(authHeader) && authHeader.startsWith("Bearer ")) {

            String token = authHeader.substring(7);

            if (token.isEmpty() || token == null || token == "undefined") {
                return chain.filter(exchange);
            }

            try {
                UserDetails userDetails = jwtService.extractUserDetails(token);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(), null, userDetails.getAuthorities());
                SecurityContext context = new SecurityContextImpl(authenticationToken);
                return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));
                // return chain.filter(exchange);
            } catch (ExpiredJwtException expiredJwtToken) {
                ServerHttpResponse response = exchange.getResponse();
                response.getHeaders().add("message", expiredJwtToken.getMessage());
                response.getHeaders().add("Location", location);
                response.setRawStatusCode(HttpStatus.SEE_OTHER.value());
                return response.setComplete();
            } catch (Exception exception) {
                log.error("Error occurred while validate the token {}", exception.getMessage());
            }
        }
        return chain.filter(exchange);
    }
}
