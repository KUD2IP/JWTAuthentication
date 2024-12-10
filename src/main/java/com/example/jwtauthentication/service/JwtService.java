package com.example.jwtauthentication.service;

import com.example.jwtauthentication.entity.User;
import com.example.jwtauthentication.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;


/**
 * Сервис для работы с JWT-токенами.
 */
@Service
public class JwtService {

    @Value("${security.jwt.secret_key}")
    private String secretKey;

    @Value("${security.jwt.access_token_expiration}")
    private long accessTokenExpiration;

    @Value("${security.jwt.refresh_token_expiration}")
    private long refreshTokenExpiration;

    private final TokenRepository tokenRepository;

    public JwtService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Проверяет, является ли токен действительным для указанного пользователя.
     *
     * @param token Токен для проверки
     * @param user Данные пользователя для сравнения
     * @return true, если токен действителен для пользователя, в противном случае false
     */
    public boolean isValid(String token, UserDetails user) {
        // Извлекаем имя пользователя из токена
        String username = extractUsername(token);

        // Проверяем, есть ли в базе данных токен с указанным значением
        boolean isValidToken = tokenRepository.findByAccessToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        // Проверяем, не истек ли токен и совпадает ли имя пользователя
        return username.equals(user.getUsername())
                && isAccessTokenExpired(token)
                && isValidToken;
    }

    /**
     * Проверяет, является ли токен обновления JWT действительным для указанного пользователя.
     *
     * @param token Токен обновления для проверки
     * @param user Данные пользователя для сравнения
     * @return true, если токен обновления действителен для пользователя, в противном случае false
     */
    public boolean isValidRefresh(String token, User user) {
        // Извлекаем имя пользователя из токена
        String username = extractUsername(token);

        // Проверяем, есть ли в базе данных токен обновления с указанным значением
        boolean isValidRefreshToken = tokenRepository.findByRefreshToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        // Проверяем, не истек ли токен обновления и совпадает ли имя пользователя
        return username.equals(user.getUsername())
                && isAccessTokenExpired(token)
                && isValidRefreshToken;
    }

    /**
     * Проверяет, истек ли срок действия токена.
     *
     * @param token Токен для проверки
     * @return true, если срок действия токена истек, в противном случае false
     */
    private boolean isAccessTokenExpired(String token) {
        return !extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    /**
     * Извлекает имя пользователя из токена.
     *
     * @param token Токен для извлечения имени пользователя
     * @return Имя пользователя, извлеченное из токена
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }


    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }


    /**
     * Извлекает все утверждения из указанного токена.
     *
     * @param token токен, из которого нужно извлечь утверждения
     * @return объект Claims, содержащий все утверждения
     */
    private Claims extractAllClaims(String token) {
        // Создаем парсер токенов JWT
        JwtParserBuilder parser = Jwts.parser();

        // Добавляем ключ для проверки подписи токена
        parser.verifyWith(getSgningKey());

        // Разбираем токен и извлекаем его утверждения
        return parser.build()
                .parseSignedClaims(token)
                .getPayload();
    }


    /**
     * Генерирует токен JWT для пользователя.
     *
     * @param user пользователь, для которого генерируется токен
     * @return сгенерированный токен JWT
     */
    public String generateAccessToken(User user) {
        // Создание объекта JwtBuilder для создания токена
        return generateToken(user, accessTokenExpiration);
    }

    /**
     * Генерирует токен обновления JWT для пользователя.
     *
     * @param user пользователь, для которого генерируется токен обновления
     * @return сгенерированный токен обновления JWT
     */
    public String generateRefreshToken(User user) {

        return generateToken(user, refreshTokenExpiration);
    }

    /**
     * Генерирует токен JWT для пользователя.
     *
     * @param user пользователь, для которого генерируется токен
     * @param expiryTime время истечения токена в миллисекундах
     * @return сгенерированный токен JWT
     */
    private String generateToken(User user, long expiryTime) {
        JwtBuilder builder = Jwts.builder()
                // Установка субъекта токена (имя пользователя)
                .subject(user.getUsername())
                // Установка времени выдачи токена (текущая дата)
                .issuedAt(new Date(System.currentTimeMillis()))
                // Установка времени истечения срока действия токена (текущая дата + 10 часов)
                .expiration(new Date(System.currentTimeMillis() + expiryTime))
                // Установка ключа для подписи токена
                .signWith(getSgningKey());

        // Создание и возврат токена в виде строки
        return builder.compact();
    }




    /**
     * Возвращает ключ подписи для JWT.
     *
     * @return SecretKey - ключ подписи для JWT
     */
    private SecretKey getSgningKey() {
        // Декодируем ключ из строки в массив байтов
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);

        // Возвращаем ключ для HmacSHA256
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
