package com.chatify.app.core.auth.handler;

import com.chatify.app.common.util.JwtUtil;
import com.chatify.app.core.auth.domain.JwtRefreshToken;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.repository.JwtRefreshTokenRepository;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.repository.UserRepository;
import com.chatify.common.response.ApiResponse; // ApiResponse 클래스를 import 합니다.
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final JwtRefreshTokenRepository jwtRefreshTokenRepository;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttributes().get("email");

        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("이메일에 해당하는 사용자가 없습니다."));

        // User 엔티티가 UserDetails를 구현하고 있어야 합니다.
        UserDetails userDetails = (UserDetails) user;

        // Access Token과 Refresh Token을 생성합니다.
        String accessToken = jwtUtil.createAccessToken(userDetails);
        JwtUtil.TokenInfo refreshTokenInfo = jwtUtil.createRefreshToken(email);
        String refreshToken = refreshTokenInfo.getToken();

        // Refresh Token을 DB에 저장합니다.
        JwtRefreshToken refreshTokenEntity = JwtRefreshToken.create(
                user,
                refreshToken,
                refreshTokenInfo.getExpiresAt(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
        jwtRefreshTokenRepository.save(refreshTokenEntity);

        // TokenResponse DTO에 토큰들을 담습니다.
        TokenResponse tokenResponse = new TokenResponse(accessToken, refreshToken);

        // ApiResponse.success()로 감싸서 최종 응답을 생성합니다.
        ApiResponse<TokenResponse> apiResponse = ApiResponse.success(HttpStatus.OK, "소셜 로그인에 성공했습니다.", tokenResponse);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
