package com.cromxt.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JwtServiceTest {

  private JwtService jwtService;
  private UserDetails userDetails;

  private Boolean getResult() {
    return Math.random() < 0.5;
  }

  @BeforeAll
  void setup() {
    jwtService = new JwtServiceImpl("B6AFCFCEB79CC14F921AEFD342D48645F43EA2C9E0B1701D3F6A0AE832388FEB", 86400000L, "test.cromxt.com");
    List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"),
        new SimpleGrantedAuthority("user:read"));
    userDetails = new User("test", "password", getResult(), getResult(), getResult(), getResult(), authorities);
  }

  @Test
  void createdJwtShouldHaveUser() {
    List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"),
        new SimpleGrantedAuthority("user:read"));
    String token = jwtService.generateToken("test", authorities, new HashMap<>());

    UserDetails extractedUser = jwtService.extractUserDetails(token);

    assertEquals("test", extractedUser.getUsername());
    assertTrue(extractedUser.isEnabled());
    assertTrue(extractedUser.isAccountNonExpired());
    assertTrue(extractedUser.isCredentialsNonExpired());
    assertTrue(extractedUser.isAccountNonLocked());
    assertIterableEquals(extractedUser.getAuthorities(), authorities);
  }

  @Test
  void createTokenFromUserDetails() {
    String token = jwtService.generateToken(userDetails);
    
    System.out.println(token);

    UserDetails extractUser = jwtService.extractUserDetails(token);

    assertEquals(extractUser.getUsername(), userDetails.getUsername());
    assertEquals(extractUser.isAccountNonExpired(), userDetails.isAccountNonExpired());
    assertEquals(extractUser.isAccountNonLocked(), userDetails.isAccountNonLocked());
    assertNotEquals(extractUser.isCredentialsNonExpired(), !userDetails.isCredentialsNonExpired());
    assertEquals(extractUser.isEnabled(), userDetails.isEnabled());
    assertIterableEquals(extractUser.getAuthorities(), userDetails.getAuthorities());
  }
}
