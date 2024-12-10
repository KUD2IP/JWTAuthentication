package com.example.jwtauthentication.handler;

import com.example.jwtauthentication.entity.Token;
import com.example.jwtauthentication.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;

    public CustomLogoutHandler(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Обработчик выхода пользователя из системы.
     * Устанавливает флаг "loggedOut" в true для соответствующего токена,
     * если токен найден в хранилище.
     *
     * @param request HttpServletRequest объект, содержащий информацию о запросе.
     * @param response HttpServletResponse объект, содержащий информацию о ответе.
     * @param authentication объект аутентификации.
     */
    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        // Получаем заголовок Authorization
        String authHeader = request.getHeader("Authorization");

        // Если заголовок не содержит JWT-токена, пропускаем фильтр
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        // Извлекаем JWT-токен из заголовка
        String token = authHeader.substring(7);

        // Ищем токен в хранилище
        Token tokenEntity = tokenRepository.findByAccessToken(token).orElse(null);

        // Если токен найден, устанавливаем флаг "loggedOut" в true
        if (tokenEntity != null) {
            tokenEntity.setLoggedOut(true);
            tokenRepository.save(tokenEntity);
        }
    }
}
