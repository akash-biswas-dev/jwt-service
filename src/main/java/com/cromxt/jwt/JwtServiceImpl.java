package com.cromxt.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtServiceImpl implements JwtService {

    private String secret;
    private String issuer;
    private Long expiration;
    private Long refreshExpiration;

    private static final String AUTHORITIES = "authorities";
    private static final String ACCOUNT_ENABLED = "accountEnabled";
    private static final String ACCOUNT_NON_EXPIRED = "accountNonExpired";
    private static final String CREDENTIALS_NON_EXPIRED = "credentialsNonExpired";
    private static final String ACCOUNT_NON_LOCKED = "accountNonLocked";


    public JwtServiceImpl(String secret, String issuer) {
      this.secret = secret;
      this.issuer = issuer;
      this.expiration = 1000L * 60 * 60 * 24;
      this.refreshExpiration = 1000L * 60 * 60 * 24 * 15;
    }

    public JwtServiceImpl(String secret, Long expiration, String issuer) {
        this.secret = secret;
        this.expiration = expiration;
        this.refreshExpiration = expiration;
        this.issuer = issuer;
    }

    public JwtServiceImpl(String secret, Long expiration, Long refreshExpiration, String issuer) {
        this.secret = secret;
        this.expiration = expiration;
        this.refreshExpiration = refreshExpiration;
        this.issuer = issuer;
    }

    @Override
    public UserDetails extractUserDetails(String token) {
        Claims claims = extractAllClaims(token);
        String userId = claims.getSubject();

        boolean enabled = claims.get(ACCOUNT_ENABLED, Boolean.class);
        boolean accountNonExpired = claims.get(ACCOUNT_NON_EXPIRED, Boolean.class);
        boolean credentialsNonExpired = claims.get(CREDENTIALS_NON_EXPIRED, Boolean.class);
        boolean accountNonLocked = claims.get(ACCOUNT_NON_LOCKED, Boolean.class);

        @SuppressWarnings("unchecked")
        List<String> authorityList = (List<String>) claims.get(AUTHORITIES, List.class);
        List<SimpleGrantedAuthority> authorities = authorityList.stream().map(SimpleGrantedAuthority::new).toList();
        return new User(userId, "no_password", enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,
                authorities);
    }

    @Override
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    @Override
    public String generateToken(String userId, Collection<? extends GrantedAuthority> grantedAuthorities,
            Map<String, Object> extraPayload) {
        Map<String, Object> extraClaims = new HashMap<>();

        List<String> authorities = getAuthorities(grantedAuthorities);

        extraClaims.put(AUTHORITIES, authorities);
        extraClaims.put(ACCOUNT_ENABLED, true);
        extraClaims.put(ACCOUNT_NON_EXPIRED, true);
        extraClaims.put(CREDENTIALS_NON_EXPIRED, true);
        extraClaims.put(ACCOUNT_NON_LOCKED, true);

        if (Objects.isNull(extraPayload) || extraPayload.isEmpty()) {
            return buildToken(userId, extraClaims, expiration);
        }
        extraPayload.keySet().forEach(eachKey -> extraClaims.put(eachKey, extraPayload.get(eachKey)));

        return buildToken(userId, extraClaims, expiration);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return generateToken(userDetails, new HashMap<>());

    }

    @Override
    public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        Map<String, Object> extraPayload = new HashMap<>();

        List<String> authorities = getAuthorities(userDetails.getAuthorities());
        extraPayload.put(AUTHORITIES, authorities);
        extraPayload.put(ACCOUNT_ENABLED, userDetails.isEnabled());
        extraPayload.put(ACCOUNT_NON_EXPIRED, userDetails.isAccountNonExpired());
        extraPayload.put(CREDENTIALS_NON_EXPIRED, userDetails.isCredentialsNonExpired());
        extraPayload.put(ACCOUNT_NON_LOCKED, userDetails.isAccountNonLocked());

        extraClaims.keySet().forEach(eachKey -> extraPayload.put(eachKey, extraClaims.get(eachKey)));
        return buildToken(userDetails.getUsername(), extraPayload,expiration);
    }

    @Override
    public String generateToken(String userId) {
        return generateToken(userId, List.of(new SimpleGrantedAuthority("ROLE_USER")), new HashMap<>());
    }

    @Override
    public String generateRefreshToken(String userId) {
        return buildToken(userId, new HashMap<>(), refreshExpiration);
    }

    @Override
    public Long getRefreshTokenExpiration() { return refreshExpiration; }
    private static List<String> getAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }

    public String generateSecret(String id) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        String data = String.format("%s-%s-%s", id, secret, System.currentTimeMillis());
        byte[] encodedHash = messageDigest.digest(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
        for (byte hash : encodedHash) {
            String hex = Integer.toHexString(0xff & hash);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    private String buildToken(String userId, Map<String, Object> claims, Long expiredAfter) {
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiredAfter))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
