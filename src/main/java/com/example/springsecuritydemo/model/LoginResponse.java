package com.example.springsecuritydemo.model;

import lombok.*;

import java.util.List;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class LoginResponse {
    private String username;
    private String token;
    private List<String> role;
}
