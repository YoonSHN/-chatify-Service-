package com.chatify.app.core.auth.service;

import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.auth.dto.response.OAuthAttributes;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.user.domain.User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface CustomOAuth2UserService {
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException;

}
