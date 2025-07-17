package com.cromxt.jwt;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {

    UserDetails extractUserDetails(String token);

    String generateToken(String userId, Collection<? extends GrantedAuthority> authorities,
            Map<String, Object> extraPayload);

    String generateToken(UserDetails userDetails, Map<String, Object> extraPayload);

    String generateToken(String userId);

    String generateToken(UserDetails userDetails);

    String generateRefreshToken(String userId);

    boolean isTokenExpired(String token);

    default Long getRefreshTokenExpiration() { return 1000L * 60 * 60 * 24 * 15; } // 15 days()
}
