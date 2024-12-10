package com.example.jwtauthentication.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    /**
     * Обработчик исключения доступа, который устанавливает статус ответа 403.
     *
     * @param request HTTP-запрос
     * @param response HTTP-ответ
     * @param accessDeniedException Исключение, указывающее на запрещенный доступ
     * @throws IOException Если произошла ошибка ввода-вывода
     * @throws ServletException Если произошла ошибка выполнения сервлета
     */
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        // Устанавливаем статус ответа 403
        response.setStatus(403);
    }
}
