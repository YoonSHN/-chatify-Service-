package com.chatify.app.core.auth.handler;

import com.chatify.app.common.util.JwtUtil;
import com.chatify.app.core.auth.domain.JwtRefreshToken;
import com.chatify.app.core.auth.repository.JwtRefreshTokenRepository;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final JwtRefreshTokenRepository refreshTokenRepository;

    @Override
    @org.springframework.transaction.annotation.Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 1. 인증된 사용자 정보를 가져옵니다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Long userId = oAuth2User.getAttribute("userId");

        // 2. DB에서 사용자 정보를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다: " + userId));

        // 3. JWT Access Token과 Refresh Token을 생성합니다.
        String accessToken = jwtUtil.createAccessToken(user.getEmail());
        JwtUtil.TokenInfo refreshTokenInfo = jwtUtil.createRefreshToken(user.getEmail());

        // 4. Refresh Token을 DB에 저장합니다.
        JwtRefreshToken refreshTokenEntity = JwtRefreshToken.create(
                user,
                refreshTokenInfo.getToken(),
                refreshTokenInfo.getExpiresAt(),
                null, null
        );
        refreshTokenRepository.save(refreshTokenEntity);

        // 5. 토큰을 URL 쿼리 파라미터에 담아 리디렉션 시킵니다.
        //    Postman 테스트를 위해 다시 Postman의 콜백 주소로 보내면,
        //    주소창에 토큰이 노출되어 복사하기 편리합니다.
        String targetUrl = UriComponentsBuilder.fromUriString("https://oauth.pstmn.io/v1/callback")
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshTokenInfo.getToken())
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        // 6. 생성된 URL로 리디렉션합니다.
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
