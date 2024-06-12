package com.example.jwtauthentication.entity;

import lombok.Getter;

@Getter
public class AuthenticationResponse {

    private final String accessToken;

    private final String refreshToken;


    public AuthenticationResponse(String token, String refreshToken) {
        this.accessToken = token;
        this.refreshToken = refreshToken;
    }

}
