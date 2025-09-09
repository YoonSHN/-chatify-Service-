package com.chatify.app.core.auth.handler;

import com.chatify.app.common.util.JwtUtil;
import com.chatify.app.core.auth.domain.JwtRefreshToken;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.repository.JwtRefreshTokenRepository;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final JwtRefreshTokenRepository jwtRefreshTokenRepository;
    private final ObjectMapper objectMapper; // JSON 변환을 위해

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        // 1. 인증 객체에서 OAuth2User 정보를 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // 2. CustomOAuth2UserService에서 반환한 속성(attributes)에서 이메일 추출
        //    (OAuthAttributes 구조에 맞게 수정 필요 시 수정)
        String email = (String) oAuth2User.getAttributes().get("email");

        // 3. 이메일로 DB에서 사용자를 조회
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 사용자가 없습니다."));

        // 4. AuthServiceImpl의 로그인 로직과 동일하게 토큰을 생성
        String accessToken = jwtUtil.createAccessToken(email);
        JwtUtil.TokenInfo refreshTokenInfo = jwtUtil.createRefreshToken(email);
        String refreshToken = refreshTokenInfo.getToken();

        // 5. Refresh Token을 DB에 저장
        JwtRefreshToken refreshTokenEntity = JwtRefreshToken.create(
                user,
                refreshToken,
                refreshTokenInfo.getExpiresAt(),
                request.getRemoteAddr(), // IP 주소
                request.getHeader("User-Agent") // 기기 정보
        );
        jwtRefreshTokenRepository.save(refreshTokenEntity);

        // 6. TokenResponse DTO에 담아 클라이언트에게 JSON 형태로 응답
        TokenResponse tokenResponse = new TokenResponse(accessToken, refreshToken);

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));
        log.info("소셜 로그인 토큰 발급 완료: {}", accessToken);
    }
}