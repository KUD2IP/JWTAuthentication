package com.example.jwtauthentication.service;


import com.example.jwtauthentication.dto.LoginDto;
import com.example.jwtauthentication.dto.RegistrationDto;
import com.example.jwtauthentication.entity.AuthenticationResponse;
import com.example.jwtauthentication.entity.Role;
import com.example.jwtauthentication.entity.Token;
import com.example.jwtauthentication.entity.User;
import com.example.jwtauthentication.repository.RoleRepository;
import com.example.jwtauthentication.repository.TokenRepository;
import com.example.jwtauthentication.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;


/**
 * Сервис аутентификации и аутентификации пользователя.
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final JwtService jwtService;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final TokenRepository tokenRepository;


    public AuthenticationService(UserRepository userRepository, RoleRepository roleRepository,
                                 JwtService jwtService,
                                 PasswordEncoder passwordEncoder,
                                 AuthenticationManager authenticationManager,
                                 TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenRepository = tokenRepository;
    }

    /**
     * Регистрация нового пользователя.
     *
     * @param request запрос на регистрацию
     *
     */
    public void register(RegistrationDto request) {
        // Создание нового пользователя
        User user = new User();

        // Заполнение полей пользователя
        user.setUsername(request.getUsername()); // устанавливаем имя пользователя
        user.setEmail(request.getEmail()); // устанавливаем электронную почту пользователя
        user.setPassword(passwordEncoder.encode(request.getPassword())); // устанавливаем пароль пользователя
        Role role= roleRepository.findByName("USER");
        user.setRole(role); // устанавливаем роль пользователя

        // Сохранение пользователя в базе данных
        user = userRepository.save(user); // сохраняем пользователя в базе данных

    }


    /**
     * Авторизация пользователя.
     *
     * @param request объект с данными пользователя для авторизации
     * @return объект с токеном авторизации
     */
    public AuthenticationResponse authenticate(LoginDto request) {
        // Авторизация пользователя
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        // Поиск пользователя по имени пользователя
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();

        String accessToken = jwtService.generateAccessToken(user); // генерируем токен авторизации
        String refreshToken = jwtService.generateRefreshToken(user); // генерируем токен обновления


        revokeAllToken(user);

        saveUserToken(accessToken, refreshToken, user);

        // Возвращение объекта с токеном авторизации
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    /**
     * Метод отзывает все действительные токены для данного пользователя.
     *
     * @param user Пользователь, для которого нужно отменить токены.
     */
    private void revokeAllToken(User user) {
        // Получаем список всех действительных токенов для данного пользователя
        List<Token> validTokens = tokenRepository.findAllAccessTokenByUser(user.getId());

        // Если список не пустой, то отменяем все токены
        if(!validTokens.isEmpty()){
            validTokens.forEach(t ->{
                // Устанавливаем признак "отменен" для каждого токена
                t.setLoggedOut(true);
            });
        }
        // Сохраняем измененные токены в базе данных
        tokenRepository.saveAll(validTokens);
    }

    /**
     * Сохраняет токен авторизации пользователя в базе данных.
     *
     * @param accessToken Токен авторизации.
     * @param refreshToken Токен обновления.
     * @param user Информация о пользователе.
     */
    private void saveUserToken(String accessToken, String refreshToken, User user) {
        // Создание объекта токена
        Token token = new Token();

        // Установка значения токена
        token.setAccessToken(accessToken);

        // Установка значения токена
        token.setRefreshToken(refreshToken);

        // Установка значения статуса токена
        token.setLoggedOut(false);

        // Установка значения пользователя
        token.setUser(user);

        // Сохранение токена в базе данных
        tokenRepository.save(token);
    }

    /**
     * Обновляет токен аутентификации.
     *
     * @param request  HTTP-запрос.
     * @param response HTTP-ответ.
     * @return Ответ с обновленным токеном.
     */
    public ResponseEntity<AuthenticationResponse> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {

        // Получаем заголовок авторизации
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Проверяем наличие и формат токена
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Извлекаем токен из заголовка
        String token = authorizationHeader.substring(7);

        // Извлекаем имя пользователя из токена
        String username = jwtService.extractUsername(token);

        // Находим пользователя по имени
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("No user found"));

        // Проверяем валидность токена обновления
        if (jwtService.isValidRefresh(token, user)) {

            // Генерируем новый доступный токен и обновляемый токен
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllToken(user);

            saveUserToken(accessToken, refreshToken, user);

            // Возвращаем новый ответ с токенами
            return new ResponseEntity<>(new AuthenticationResponse(accessToken, refreshToken), HttpStatus.OK);
        }

        // Возвращаем неавторизованный статус
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
