package com.smartkhata.authentication.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

// JwtUtil is responsible for creating, signing, parsing, and validating JWT tokens using a secret key and expiration time.

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    // JWT does not accept plain strings It needs a Key object
    private Key getSigningkey(){
        return Keys.hmacShaKeyFor(secret.getBytes());   // Converts secret string → cryptographic key
    }

    // After successfull call this will called
    public String generateToken(UserDetails userDetails){

        return Jwts.builder()
                .setSubject(userDetails.getUsername())  // who this token belongs to
                .claim("roles",userDetails.getAuthorities()
                        .stream()
                        .map(auth -> auth.getAuthority())
                        .toList())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+expiration))
                .signWith(getSigningkey(), SignatureAlgorithm.HS256)    // Signs token using secret key Prevents tampering
                .compact();     // Converts everything into JWT string
    }

    //  Reads token & Extracts email/username (Check who is this ?)
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    // checks Expiry date. If expired → invalid
    public boolean isTokenValid(String token){
        return !parseClaims(token).getExpiration().before(new Date());
    }

    // This code parses and validates a JWT by verifying its signature using the secret key and then extracts the claims (payload) if the token is authentic and not expired.
    private Claims parseClaims(String token) {
        // Claims = data inside token
        return Jwts.parserBuilder() // Starts creating a JWT parser object

                .setSigningKey(getSigningkey()) // Provides the secret key
                // (internally)
                // JWT library:
                    // Takes header + payload
                    // Recreates signature using secret key
                    // Compares with token’s signature

                .build()    // Finalizes the parser configuration

                .parseClaimsJws(token)
                /* WHAT THIS DOES (ALL IN ONE)
                    1. Splits token into 3 parts
                    2. Base64-decodes header & payload
                    3. Recalculates signature
                    4. Compares signatures
                    5. Checks expiration (exp)
                    6. Throws exception if ANY check fails
                */
                .getBody();     // Extracts payload (claims) that contains: username, roles, issued time, expiry time

        /*
            returns claims like map below:
                claims.getSubject()
                claims.get("roles")
                claims.getExpiration()
        */
    }
}
