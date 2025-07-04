package com.cromxt.jwt;


import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Map;

public interface JwtService {

    UserDetails extractUserDetails(String token);

    String generateToken(String userId, List<String> authorities, Map<String, Object> extraPayload);

    boolean isTokenExpired(String token);
}
