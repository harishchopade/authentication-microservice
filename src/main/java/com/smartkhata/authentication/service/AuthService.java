package com.smartkhata.authentication.service;

import com.smartkhata.authentication.entity.User;
import com.smartkhata.authentication.enums.Role;
import com.smartkhata.authentication.repository.UserRepository;
import com.smartkhata.authentication.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;          // Core Spring Security component that Verifies email + password
    private final JwtUtil jwtUtil;      // Generates JWT token
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public String login(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        /*
            Spring Security now:
                1. Calls UserDetailsService
                2. Loads user from DB
                3. Compares passwords (using BCrypt)
                4. Checks account status
                5. Returns authenticated object OR throws exception

            What it contains after success
                UserDetails (principal) // Principal = The authenticated user Returned from UserDetailsService
                Authorities (roles)
                Authentication status = true
         */

        return jwtUtil.generateToken((UserDetails) authentication.getPrincipal());
        /*
            What happens here:
                Username + roles embedded in token
                Token signed
                Token expiry set
         */
    }

    public void signup(String email, String password, String role){

        if(userRepository.findByEmail(email).isPresent()){
            throw new RuntimeException("User already Exist");
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));

        Role assignedRole;

        if (role == null || role.isBlank()){
            assignedRole = Role.USER;
        } else {
            assignedRole = Role.valueOf(role.toUpperCase());
        }

        user.setRoles(assignedRole.withPrefix());

        userRepository.save(user);
    }
}
