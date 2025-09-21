package com.chatify.app.common.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JWT(Json Web Token) 생성, 검증 및 관련 유틸리티를 제공하는 클래스입니다.
 * Access Token, Refresh Token, 이메일 인증용 임시 토큰 등
 * 애플리케이션의 모든 JWT 관련 로직을 담당합니다.
 */
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

    /**
     * 토큰 문자열과 만료 시간을 담는 내부 DTO 클래스입니다.
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


    // =================================================================================
    // =                            Public: 토큰 생성 메서드                            =
    // =================================================================================

    /**
     * Access Token을 생성합니다.
     * @param userDetails 사용자 정보를 담은 UserDetails 객체
     * @return 생성된 Access Token 문자열
     */
    public String createAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // 권한 정보를 쉼표로 구분된 문자열로 저장
        String authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        claims.put("auth", authorities);

        return createToken(userDetails.getUsername(), accessTokenValidityInMs, claims).getToken();
    }

    /**
     * Refresh Token을 생성합니다. (추가 정보 없이 이메일만 담음)
     * @param email 사용자 이메일
     * @return 생성된 Refresh Token 정보 (토큰 + 만료 시간)
     */
    public TokenInfo createRefreshToken(String email) {
        return createToken(email, refreshTokenValidityInMs, new HashMap<>());
    }

    /**
     * 이메일 인증 '대기' 상태를 나타내는 임시 토큰을 생성합니다.
     * @param email 사용자 이메일
     * @return 생성된 인증 대기 토큰 문자열
     */
    public String createPendingToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("status", "PENDING_VERIFICATION");
        return createToken(email, pendingTokenValidityInMs, claims).getToken();
    }

    /**
     * 이메일 인증 '성공' 상태를 나타내는 임시 토큰을 생성합니다.
     * @param email 사용자 이메일
     * @return 생성된 인증 성공 토큰 문자열
     */
    public String createSuccessToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("status", "SUCCESS");
        return createToken(email, successTokenValidityInMs, claims).getToken();
    }


    // =================================================================================
    // =                           Public: 토큰 검증 및 추출 메서드                        =
    // =================================================================================

    /**
     * 토큰에서 사용자 이메일(Subject)을 추출합니다.
     * @param token JWT 토큰
     * @return 사용자 이메일
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 토큰이 유효한지 검증합니다. (사용자 정보 일치 + 만료 여부)
     * @param token JWT 토큰
     * @param userDetails 검증할 사용자 정보
     * @return 토큰 유효 여부 (true: 유효, false: 유효하지 않음)
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * 이메일 인증용 토큰의 유효성을 검증하고, 특정 상태(status)를 포함하는지 확인합니다.
     * @param token 검증할 토큰
     * @param requiredStatus 필요한 상태 값 (예: "SUCCESS")
     * @return 토큰이 유효하고 필요한 상태를 가지면 사용자 이메일을 반환
     * @throws IllegalArgumentException 상태가 일치하지 않거나 없을 경우
     */
    public String validateAndGetEmail(String token, String requiredStatus) {
        Claims claims = extractAllClaims(token);
        String status = claims.get("status", String.class);
        if (status == null || !status.equals(requiredStatus)) {
            throw new IllegalArgumentException("토큰의 상태가 유효하지 않습니다.");
        }
        return claims.getSubject();
    }


    // =================================================================================
    // =                          Private: 내부 헬퍼 메서드                             =
    // =================================================================================

    /**
     * 토큰이 만료되었는지 확인합니다.
     * @param token 검사할 토큰
     * @return 만료 여부 (true: 만료됨, false: 유효함)
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * 토큰에서 만료 시간을 추출합니다.
     * @param token JWT 토큰
     * @return 만료 시간 Date 객체
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * 토큰에서 모든 Claim(정보 조각)을 추출합니다.
     * @param token JWT 토큰
     * @return 모든 Claim이 담긴 Claims 객체
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 토큰에서 특정 Claim을 추출하는 제네릭 메서드입니다.
     * @param token JWT 토큰
     * @param claimsResolver 추출할 Claim을 지정하는 함수
     * @return 추출된 Claim
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 모든 토큰 생성을 담당하는 핵심 private 메서드입니다.
     * @param subject 토큰의 주체 (사용자 이메일)
     * @param validityInMs 토큰의 유효 기간 (밀리초)
     * @param claims 토큰에 담을 추가 정보 (예: 권한, 상태 등)
     * @return 생성된 토큰 정보 (토큰 문자열 + 만료 시간)
     */
    private TokenInfo createToken(String subject, long validityInMs, Map<String, Object> claims) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMs);

        String token = Jwts.builder()
                .setClaims(claims) // 추가 정보 먼저 설정
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey)
                .compact();

        return new TokenInfo(token, validity);
    }
}