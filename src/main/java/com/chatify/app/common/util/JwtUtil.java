package com.chatify.app.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

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

    public TokenInfo createRefreshToken(String email) {
        return createToken(email, refreshTokenValidityInMs);
    }

    // --- 이메일 인증용 토큰 생성 ---
    public String createPendingToken(String email) {
        return createVerificationToken(email, "PENDING_VERIFICATION", pendingTokenValidityInMs);
    }

    public String createSuccessToken(String email) {
        return createVerificationToken(email, "SUCCESS", successTokenValidityInMs);
    }


    // --- 토큰 검증 및 추출 메서드 (필터에서 사용) ---

    /**
     * 토큰에서 사용자 이메일(username)을 추출합니다.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 토큰이 유효한지 검증합니다. (사용자 정보 일치 + 만료 여부)
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // --- 기존 검증 메서드 ---
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


    // --- 내부 private 헬퍼 메서드 ---

    /**
     * 토큰이 만료되었는지 확인합니다.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * 토큰에서 만료 시간을 추출합니다.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * 토큰에서 특정 Claim을 추출하는 제네릭 메서드입니다.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 토큰에서 모든 Claim을 추출합니다.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

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