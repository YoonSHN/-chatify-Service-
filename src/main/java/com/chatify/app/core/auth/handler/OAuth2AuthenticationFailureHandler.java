package com.chatify.app.core.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
// SimpleUrlAuthenticationFailureHandler를 상속받아 리다이렉트 로직을 쉽게 구현합니다.
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.error("OAuth2 인증 실패: {}", exception.getMessage(), exception);

        // 실패 시 리다이렉트할 프론트엔드의 URL
        // 실제 운영에서는 application.yml 같은 설정 파일에서 관리하는 것이 좋습니다.
        String targetUrl = "http://localhost:3000/login";

        // URL에 에러 메시지를 쿼리 파라미터로 추가하여 리다이렉트
        // UriComponentsBuilder를 사용하면 URL을 안전하게 생성할 수 있습니다.
        String redirectUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", "social_login_failed")
                .queryParam("message", getExceptionMessage(exception))
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        // 부모 클래스의 메서드를 사용하여 리다이렉트 로직을 수행
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    /**
     * 발생한 예외에 따라 사용자에게 보여줄 메시지를 결정합니다.
     * @param exception 발생한 인증 예외
     * @return 클라이언트에게 전달할 에러 메시지
     */
    private String getExceptionMessage(AuthenticationException exception) {
        // OAuth2AuthenticationException의 하위 클래스들을 확인하여 더 구체적인 메시지 제공 가능
        // 예: if (exception instanceof OAuth2AuthorizationCodeExchangeException) { ... }
        return "소셜 로그인 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.";
    }
}