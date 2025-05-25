package com.example.spring_security.user.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterUserDto {
    private String email;
    private String fullname;
    private String password;
}
