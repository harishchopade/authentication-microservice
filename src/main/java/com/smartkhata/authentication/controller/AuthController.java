package com.smartkhata.authentication.controller;

import com.smartkhata.authentication.dto.LoginRequest;
import com.smartkhata.authentication.dto.LoginResponse;
import com.smartkhata.authentication.dto.SignupRequest;
import com.smartkhata.authentication.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.smartkhata.authentication.entity.User;
import com.smartkhata.authentication.repository.UserRepository;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor        // Injects required dependencies automatically
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request){
        String token = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(new LoginResponse(token));
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        authService.signup(request.getEmail(), request.getPassword(), request.getRoles());
        return ResponseEntity.ok("User registered Successfully");
    }
}
