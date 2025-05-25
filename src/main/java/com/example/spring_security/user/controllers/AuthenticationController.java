package com.example.spring_security.user.controllers;

import org.springframework.web.bind.annotation.RestController;

import com.example.spring_security.user.dtos.LoginResponseDto;
import com.example.spring_security.user.dtos.LoginUserDto;
import com.example.spring_security.user.dtos.RegisterUserDto;
import com.example.spring_security.user.models.User;
import com.example.spring_security.user.services.AuthenticationService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController()
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(
        AuthenticationService authenticationService
    ) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginUserDto loginDto) {
        LoginResponseDto loginResponse = authenticationService.login(loginDto);
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerDto) {
        User user = this.authenticationService.register(registerDto);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getDetails();
        User user = new User();
        return ResponseEntity.ok(user);
    }
    
    
    
}
