package com.chatify.app.core.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
// SimpleUrlAuthenticationFailureHandler를 상속받아 리다이렉트 로직을 쉽게 구현합니다.
public class OAuth2LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // 인증 실패시 메인 페이지로 이동
        response.sendRedirect("http://localhost:8080/");
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