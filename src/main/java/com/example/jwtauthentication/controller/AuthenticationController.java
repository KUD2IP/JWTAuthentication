package com.example.jwtauthentication.controller;


import com.example.jwtauthentication.dto.LoginDto;
import com.example.jwtauthentication.dto.RegistrationDto;
import com.example.jwtauthentication.entity.AuthenticationResponse;
import com.example.jwtauthentication.entity.User;
import com.example.jwtauthentication.service.AuthenticationService;
import com.example.jwtauthentication.service.UserService;
import jakarta.persistence.GeneratedValue;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;


@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserService userService;

    public AuthenticationController(AuthenticationService authenticationService, UserService userService) {
        this.authenticationService = authenticationService;
        this.userService = userService;
    }


    /**
     * Регистрация нового пользователя.
     *
     * @param registrationDto данные для регистрации
     * @return ответ о результате регистрации
     */
    @PostMapping("/registration")
    public ResponseEntity<String> register(
            @RequestBody RegistrationDto registrationDto
    ) {
        // Проверка наличия пользователя с таким же именем
        if(userService.existsByUsername(registrationDto.getUsername())) {
            return ResponseEntity.badRequest().body("Имя пользователя уже занято");
        }
        // Проверка наличия пользователя с таким же email
        if(userService.existsByEmail(registrationDto.getEmail())) {
            return ResponseEntity.badRequest().body("Email уже занят");
        }

        // Регистрация нового пользователя
        authenticationService.register(registrationDto);

        return ResponseEntity.ok("Регистрация прошла успешно");
    }


    @GetMapping("/registration")
    public ModelAndView registration() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("registration");
        return modelAndView;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody LoginDto request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/login")
    public ModelAndView login() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("login");
        return modelAndView;
    }


    @PostMapping("/refresh_token")
    public ResponseEntity refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return authenticationService.refreshToken(request, response);
    }
}
