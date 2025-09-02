package com.chatify.app.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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

    private final Key secretKey;
    private final long pendingTokenValidityInMs;
    private final long successTokenValidityInMs;
    private final long accessTokenValidityInMs;
    private final long refreshTokenValidityInMs;

    public JwtUtil(
            @Value("${jwt.secret-key}") String secret,
            @Value("${jwt.pending-token-expiration-ms}") long pendingTokenValidityInMs,
            @Value("${jwt.success-token-expiration-ms}") long successTokenValidityInMs,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenValidityInMs,
            @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenValidityInMs){

            byte[] keyBytes = Decoders.BASE64.decode(secret);
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            this.pendingTokenValidityInMs = pendingTokenValidityInMs;
            this.successTokenValidityInMs = successTokenValidityInMs;
            this.accessTokenValidityInMs = accessTokenValidityInMs;
            this.refreshTokenValidityInMs = refreshTokenValidityInMs;
    }
    public String createPendingToken(String email){
        return createVerificationToken(email, "PENDING_VERIFICATION", pendingTokenValidityInMs);
    }

    public String createSuccessToken(String email){
        return createVerificationToken(email, "SUCCESS", successTokenValidityInMs);
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

    public String createAccessToken(String email) {
        // Access Token에는 'roles' 같은 권한 정보를 담는 것이 일반적입니다.
        // 예: .claim("roles", "USER")
        return createToken(email, accessTokenValidityInMs);
    }

    //인증상태를 담은 임시 토큰 생성
    public String  createVerificationToken(String email, String status, long tokenValidityInMs){
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
    //토큰 검증 하고 이메일과 상태를 확인하는 메서드
    public String validateAndGetEmail(String token, String requiredStatus){
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String status = claims.get("status", String.class);
        if(status == null || !status.equals(requiredStatus)){
            throw new IllegalArgumentException("토큰의 상태가 유효하지 않습니다.");
        }

        return claims.getSubject();
    }
}
