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
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final JwtRefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper;

    @Override
    @org.springframework.transaction.annotation.Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 1. 인증된 사용자 정보를 OAuth2User 객체로 캐스팅합니다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Long userId = oAuth2User.getAttribute("userId"); // CustomOAuth2UserService에서 넣은 userId

        // 2. DB에서 완전한 User 엔티티 정보를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        // 3. JWT Access Token과 Refresh Token을 생성합니다.
        String accessToken = jwtUtil.createAccessToken(user.getEmail());
        JwtUtil.TokenInfo refreshTokenInfo = jwtUtil.createRefreshToken(user.getEmail());

        // 4. Refresh Token을 DB에 저장하거나 업데이트합니다.
        JwtRefreshToken refreshTokenEntity = JwtRefreshToken.create(
                user,
                refreshTokenInfo.getToken(),
                refreshTokenInfo.getExpiresAt(),
                null, null
        );
        refreshTokenRepository.save(refreshTokenEntity);

        // 5. Postman 테스트를 위해 리디렉션 대신 JSON 응답을 직접 작성합니다.
        TokenResponse tokenResponse = new TokenResponse(accessToken, refreshTokenInfo.getToken());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(tokenResponse));

        log.info("소셜 로그인 성공. JWT 발급 완료. User ID: {}", userId);

        // --- 실제 프론트엔드와 연동 시 사용할 리디렉션 로직 (참고용) ---
        // String targetUrl = UriComponentsBuilder.fromUriString("http://your-frontend.com/login-success")
        //         .queryParam("accessToken", accessToken)
        //         .queryParam("refreshToken", refreshTokenInfo.getToken())
        //         .build().toUriString();
        // getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}