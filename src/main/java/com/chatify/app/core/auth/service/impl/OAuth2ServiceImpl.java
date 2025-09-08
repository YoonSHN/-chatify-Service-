package com.chatify.app.core.auth.service.impl;

import com.chatify.app.common.util.JwtUtil;
import com.chatify.app.core.auth.domain.JwtRefreshToken;
import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.auth.domain.SocialAccount;
import com.chatify.app.core.auth.dto.response.OAuthAttributes;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.repository.JwtRefreshTokenRepository;
import com.chatify.app.core.auth.repository.SocialAccountRepository;
import com.chatify.app.core.auth.service.OAuth2Service;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.domain.UserProfile;
import com.chatify.app.core.user.domain.UserSettings;
import com.chatify.app.core.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuth2ServiceImpl implements OAuth2Service {
    private final InMemoryClientRegistrationRepository clientRegistrationRepository;
    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;
    private final JwtRefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    @Transactional
    public TokenResponse socialLogin(Provider provider, String authorizationCode) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider.name().toLowerCase());
        String accessToken = getAccessToken(clientRegistration, authorizationCode);
        OAuthAttributes attributes = getUserProfile(provider, clientRegistration, accessToken);

        User user = findOrCreateUser(attributes);

        return issueServiceTokens(user);
    }

    private User findOrCreateUser(OAuthAttributes attributes) {
        Optional<SocialAccount> socialAccountOptional = socialAccountRepository.findByProviderAndProviderUserId(
                attributes.getProvider(), attributes.getProviderUserId());

        if (socialAccountOptional.isPresent()) {
            return socialAccountOptional.get().getUser();
        }

        Optional<User> userOptional = userRepository.findUserByEmail(attributes.getEmail());

        if (userOptional.isPresent()) {
            User existingUser = userOptional.get();
            connectSocialAccount(existingUser, attributes);
            return existingUser;
        }

        return createNewUser(attributes);
    }

    private User createNewUser(OAuthAttributes attributes) {
        User newUser = User.builder()
                .email(attributes.getEmail())
                .password(null)
                .build();

        UserProfile userProfile = UserProfile.create(newUser, attributes.getName(), null);
        UserSettings userSettings = UserSettings.create(newUser);
        newUser.setUserProfile(userProfile);
        newUser.setUserSettings(userSettings);

        userRepository.save(newUser);

        connectSocialAccount(newUser, attributes);

        return newUser;
    }

    private void connectSocialAccount(User user, OAuthAttributes attributes) {
        SocialAccount socialAccount = SocialAccount.create(user, attributes.getProvider(), attributes.getProviderUserId());
        socialAccountRepository.save(socialAccount);
    }

    private TokenResponse issueServiceTokens(User user) {
        String accessToken = jwtUtil.createAccessToken(user.getEmail());
        JwtUtil.TokenInfo refreshTokenInfo = jwtUtil.createRefreshToken(user.getEmail());

        JwtRefreshToken refreshTokenEntity = JwtRefreshToken.create(
                user,
                refreshTokenInfo.getToken(),
                refreshTokenInfo.getExpiresAt(),
                null, null
        );
        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(accessToken, refreshTokenInfo.getToken());
    }

    // --- 외부 소셜 서비스와 통신하는 private 헬퍼 메서드들 (완성본) ---

    /**
     * 소셜 서버로 Authorization Code를 보내 Access Token을 받아옵니다.
     */
    private String getAccessToken(ClientRegistration provider, String authorizationCode) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("client_id", provider.getClientId());
        formData.add("client_secret", provider.getClientSecret());
        formData.add("redirect_uri", provider.getRedirectUri());
        formData.add("code", authorizationCode);

        Map<String, Object> response = WebClient.create()
                .post()
                .uri(provider.getProviderDetails().getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(formData)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        return (String) response.get("access_token");
    }

    /**
     * 소셜 서버로 Access Token을 보내 사용자 프로필 정보를 받아옵니다.
     */
    private OAuthAttributes getUserProfile(Provider providerType, ClientRegistration provider, String accessToken) {
        Map<String, Object> userAttributes = WebClient.create()
                .get()
                .uri(provider.getProviderDetails().getUserInfoEndpoint().getUri())
                .headers(header -> header.setBearerAuth(accessToken))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        String userNameAttributeName = provider.getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        // Naver의 경우 응답 JSON이 response 객체로 한 번 더 감싸져 있습니다.
        if ("naver".equalsIgnoreCase(providerType.name())) {
            userAttributes = (Map<String, Object>) userAttributes.get(userNameAttributeName);
        }

        return OAuthAttributes.of(providerType, userAttributes);
    }
}
