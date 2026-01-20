## 🔐 How to Secure Another Microservice

This authentication service is **fully independent** and **reusable**.  
It **must not be modified** when integrating with other services.

---

### 🔁 Authentication Flow

- 🔑 Client authenticates using this service
- 🪪 JWT token is issued
- 📤 Client sends JWT with every request
- 🛡️ Other microservices validate the token

---

### 🧩 What the Other Microservice Must Do

- 📥 Read the `Authorization` header from every request
- ✂️ Extract the JWT token
- 🔍 Validate token signature & expiry
- ✅ Allow request if token is valid
- ❌ Reject request with **401 Unauthorized** if invalid

---

### ⚙️ Security Expectations

- 🧠 Stateless architecture (no sessions)
- 🚫 CSRF disabled
- 🔐 JWT-based authentication only
- 🧩 Token validation before controller execution

---

### 👥 Role & Access Control

- 🏷️ Extract roles from JWT claims
- 🔒 Protect endpoints using roles
- 🎯 Keep authorization logic local to the service

---

### 🚫 Important Rules

- ❌ Do NOT modify this authentication service
- ❌ Do NOT re-authenticate users
- ❌ Do NOT store sessions
- ✅ Trust only JWTs issued by this service

---

### ✅ Final Result

- 🔒 Centralized authentication
- 🧩 Independent microservices
- 📈 Scalable system

---

## 🔐 Security Integration Example (Other Microservice)

This section demonstrates the **security-related files** required in another
microservice to integrate with this Authentication Service.

### 📁 Security Files Overview

- `JwtUtil.java`
- `JwtAuthenticationFilter.java`
- `SecurityConfig.java`
- `application.yml`

---

### 📄 JwtUtil.java

```java

import java.security.Key;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
    
    @Value("${jwt.secret}")
    private String secret;
    
    private Key getSigningKey(){
        return Keys.hmacShaKeyFor(secret.getBytes());   
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()                 
                .setSigningKey(getSigningKey())     
                .build()                            
                .parseClaimsJws(token)                
                .getBody();                         
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();      
    }

    public List<String> extractRoles(String token) {
        return extractClaims(token).get("roles", List.class);
    }

    public boolean isTokenValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

```
### 📄 JwtAuthenticationFilter.java
```java

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String header = request.getHeader("Authorization");

        if(header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            if (jwtUtil.isTokenValid(token)) {
                
                String username = jwtUtil.extractUsername(token);
                List<String> roles = jwtUtil.extractRoles(token);
                
                List<SimpleGrantedAuthority> authorities = roles.stream()
                                                                .map(SimpleGrantedAuthority::new)
                                                                .toList();
                
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication); user.”
            }
        }

        filterChain.doFilter(request, response);        
    }    
}

```
### 📄 SecurityConfig.java
```java

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;

@EnableMethodSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())   
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))               
            .authorizeHttpRequests(auth -> auth                     
                .requestMatchers("/public/**").permitAll()          
                .requestMatchers("/admin/**").hasRole("ADMIN")      
                .anyRequest().authenticated()                       
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);            

        return http.build();
    }
}

```

### Application.yml
```yml
jwt:
  secret: my-secret-key-which-is-very-long-and-difficult
spring:
  security:
    user:
      name: disabled
      password: disabled

