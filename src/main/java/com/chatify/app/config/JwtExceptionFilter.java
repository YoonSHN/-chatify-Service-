package com.chatify.app.config;

import com.chatify.common.response.ApiResponse; // ApiResponse 클래스를 import 합니다.
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtExceptionFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException ex) {
            // JwtAuthenticationFilter에서 발생한 예외를 여기서 처리합니다.
            setErrorResponse(response, ex);
        }
    }

    private void setErrorResponse(HttpServletResponse response, JwtException ex) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value()); // 401 상태 코드 설정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // 직접 만든 ApiResponse.fail()을 사용하여 일관된 에러 응답을 생성합니다.
        ApiResponse<?> apiResponse = ApiResponse.fail(HttpStatus.UNAUTHORIZED, ex.getMessage());

        objectMapper.writeValue(response.getWriter(), apiResponse);
    }
}
