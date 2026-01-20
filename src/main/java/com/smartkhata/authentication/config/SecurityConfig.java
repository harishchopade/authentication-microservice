package com.smartkhata.authentication.config;

import com.smartkhata.authentication.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


// SecurityConfig defines the security rules of the application
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Builder object Used to configure security rules
        http
                .csrf(csrf -> csrf.disable())
                /*
                    What is CSRF?
                        Protection for session + cookies
                    Why disable here?
                        Your app is:
                            JWT based
                            Stateless
                            Token in header
                    So CSRF is not required
                 */

                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                /*
                    What this means:
                        Spring Security will NOT create session
                        Every request must bring JWT
                    📌 “No memory of users — show ID every time”
                 */

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login", "/auth/signup").permitAll()         // Anyone can access login No token required
                        .anyRequest().authenticated())          // Every other URL needs JWT  If no token → 401 error

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
                /*
                    What this means
                        Insert your JWT filter
                        Run it before Spring’s default login filter

                    Why BEFORE?
                        JWT should authenticate user
                        So Spring Security already knows the user
                 */

        return http.build();
    }


    // Spring Security does not auto-create an AuthenticationManager bean, so it must be explicitly defined using AuthenticationConfiguration.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
