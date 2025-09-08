package com.chatify.app.config;

import com.chatify.app.core.auth.handler.OAuth2AuthenticationFailureHandler;
import com.chatify.app.core.auth.handler.OAuth2AuthenticationSuccessHandler;
import com.chatify.app.core.auth.service.CustomOAuth2UserService;
import com.chatify.app.config.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())

                .authorizeHttpRequests(auth -> auth
                        // 소셜 로그인과 관련된 기본 경로는 모두 허용해야 합니다.
                        .requestMatchers("/login/**", "/oauth2/**").permitAll()
                        // 이메일 인증 등, 인증 없이 접근해야 하는 다른 API 경로
                        .requestMatchers("/api/auth/emails/**").permitAll()
                        .anyRequest().authenticated()
                )

                // OAuth2 로그인 설정을 시작합니다.
                .oauth2Login(oauth2 -> oauth2
                        // 인증 성공 후 사용자 정보를 가져올 때 사용할 서비스를 지정합니다.
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        // 인증 성공 시 실행될 핸들러를 지정합니다.
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        // 인증 실패 시 실행될 핸들러를 지정합니다.
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                )

                // 모든 요청에 대해 JWT 필터를 적용합니다.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
