package com.chatify.app.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Component
public class JwtUtil {

    // ... (기존 필드 및 생성자) ...
    private final Key secretKey;
    private final long accessTokenValidityInMs;
    private final long refreshTokenValidityInMs;
    private final long pendingTokenValidityInMs;
    private final long successTokenValidityInMs;

    public JwtUtil(
            @Value("${jwt.secret-key}") String secret,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenValidityInMs,
            @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenValidityInMs,
            @Value("${jwt.pending-token-expiration-ms}") long pendingTokenValidityInMs,
            @Value("${jwt.success-token-expiration-ms}") long successTokenValidityInMs) {

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidityInMs = accessTokenValidityInMs;
        this.refreshTokenValidityInMs = refreshTokenValidityInMs;
        this.pendingTokenValidityInMs = pendingTokenValidityInMs;
        this.successTokenValidityInMs = successTokenValidityInMs;
    }

    /**
     * 토큰과 만료 시간을 함께 담는 내부 DTO 클래스
     */
    @Getter
    public static class TokenInfo {
        private final String token;
        private final LocalDateTime expiresAt;

        private TokenInfo(String token, Date expiresAtDate) {
            this.token = token;
            this.expiresAt = Instant.ofEpochMilli(expiresAtDate.getTime())
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
        }
    }
    // --- 로그인용 토큰 생성 ---

    public String createAccessToken(String email) {
        return createToken(email, accessTokenValidityInMs).getToken();
    }

    /**
     * Refresh Token을 생성하고, 토큰 정보(문자열, 만료시간)를 반환합니다.
     */
    public TokenInfo createRefreshToken(String email) {
        return createToken(email, refreshTokenValidityInMs);
    }

    // ... (기존 이메일 인증용 토큰 생성 메서드) ...
    public String createPendingToken(String email) {
        return createVerificationToken(email, "PENDING_VERIFICATION", pendingTokenValidityInMs);
    }
    public String createSuccessToken(String email) {
        return createVerificationToken(email, "SUCCESS", successTokenValidityInMs);
    }

    // --- 토큰 검증 메서드 ---

    // ... (기존 검증 메서드) ...
    public String validateAndGetEmail(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    public String validateAndGetEmail(String token, String requiredStatus) {
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
        String status = claims.get("status", String.class);
        if (status == null || !status.equals(requiredStatus)) {
            throw new IllegalArgumentException("토큰의 상태가 유효하지 않습니다.");
        }
        return claims.getSubject();
    }


    // --- 내부 private 메서드 ---

    private TokenInfo createToken(String email, long validityInMs) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMs);

        String token = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey)
                .compact();

        return new TokenInfo(token, validity);
    }

    private String createVerificationToken(String email, String status, long tokenValidityInMs) {
        // ... (기존과 동일) ...
        Date now = new Date();
        Date validity = new Date(now.getTime() + tokenValidityInMs);
        return Jwts.builder()
                .setSubject(email)
                .claim("status", status)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey)
                .compact();
    }
}