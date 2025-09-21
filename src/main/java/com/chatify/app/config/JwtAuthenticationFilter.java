package com.chatify.app.config;

import com.chatify.app.common.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService; // UserRepository 대신 UserDetailsService를 주입받습니다.

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // 1. Authorization 헤더가 없거나 "Bearer "로 시작하지 않으면,
        //    JWT 토큰이 없는 요청이므로 다음 필터로 바로 넘어갑니다.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 2. "Bearer " 부분을 제외한 순수 JWT 토큰을 추출합니다.
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtUtil.extractUsername(jwt);

            // 3. 토큰에서 이메일을 추출했고, 아직 SecurityContext에 인증 정보가 없다면 인증 절차를 시작합니다.
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 4. UserDetailsService를 통해 DB에서 사용자 정보를 가져옵니다.
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // 5. 가져온 사용자 정보로 토큰이 유효한지 최종 검증합니다.
                if (jwtUtil.isTokenValid(jwt, userDetails)) {
                    // 6. 토큰이 유효하다면, Spring Security가 사용할 인증 토큰(Authentication)을 생성합니다.
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null, // JWT 방식에서는 비밀번호를 사용하지 않으므로 null
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // 7. SecurityContextHolder에 인증 정보를 저장합니다.
                    //    이제부터 이 요청은 '인증된' 요청으로 처리됩니다.
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            // 다음 필터로 요청과 응답을 전달합니다.
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            // 토큰 파싱/검증 과정에서 예외 발생 시, JwtException으로 감싸서 던집니다.
            // 이 예외는 바로 앞단에 위치한 JwtExceptionFilter에서 처리됩니다.
            log.error("JWT 인증 필터에서 에러 발생: {}", e.getMessage());
            throw new JwtException("유효하지 않은 토큰입니다. 다시 로그인해주세요.");
        }
    }
}