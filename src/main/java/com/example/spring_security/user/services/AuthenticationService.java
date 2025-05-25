package com.example.spring_security.user.services;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.spring_security.jwt.JwtService;
import com.example.spring_security.user.dtos.LoginResponseDto;
import com.example.spring_security.user.dtos.LoginUserDto;
import com.example.spring_security.user.dtos.RegisterUserDto;
import com.example.spring_security.user.models.User;
import com.example.spring_security.user.repository.UserRepository;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public User register(RegisterUserDto registerDto) {
        User user = new User();
        user.setEmail(registerDto.getEmail());
        user.setFullName(registerDto.getFullname());
        String encodedPassword = passwordEncoder.encode(registerDto.getPassword());
        user.setPassword(encodedPassword);
        User savedUser = this.userRepository.save(user);
        return savedUser;
    }

    public LoginResponseDto login(LoginUserDto loginDto) {
        UsernamePasswordAuthenticationToken loginData = new UsernamePasswordAuthenticationToken(loginDto.getEmail(),
                loginDto.getPassword());
        try {
            authenticationManager.authenticate(loginData);
            Optional<User> user = userRepository.findByEmail(loginDto.getEmail());
            String token = jwtService.generateToken(user.get());
            long expiredTime = jwtService.getExpirationTime();
            LoginResponseDto loginResponseDto = new LoginResponseDto();
            loginResponseDto.setExpiredTime(expiredTime);
            loginResponseDto.setToken(token);
            return loginResponseDto;
        } catch (Exception e) {
            throw e;
        }
    }
}
