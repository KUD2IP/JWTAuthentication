package com.example.jwtauthentication.service;

import com.example.jwtauthentication.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

}
