package com.smartkhata.authentication.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {     // Each HTTP request must be checked exactly once that prevents duplicate authentication

    private final JwtUtil jwtUtil;
    private final CustomeUserDetailsService customeUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if(header != null && header.startsWith("Bearer ")){     // Tells server token type

            String token = header.substring(7);     // "Bearer " → 7 characters = Removes prefix and gets actual token.

            String username = jwtUtil.extractUsername(token);

            if (username != null
                    && SecurityContextHolder.getContext().getAuthentication() == null       // Prevents double authentication i.e. if user is authenticated first then this should not be run
                    && jwtUtil.isTokenValid(token)) {

                UserDetails userDetails = customeUserDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                /* this means
                    User is authenticated,
                    Password not needed (already verified),
                    Authorities assigned
                 */

                SecurityContextHolder.getContext().setAuthentication(auth);
                /* This tells Spring Security:
                    "User is authenticated for THIS request."
                    After this:
                        Controllers can access user
                        Authorization works
                 */
            }
        }

        filterChain.doFilter(request, response);
        /*
            Why needed?
                Pass request to:
                    Controller
                    Next filters
                    Without this → request stops ❌
         */
    }
}
