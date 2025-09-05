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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        OAuthAttributes attributes = getUserProfile(clientRegistration, accessToken);

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
//
//    // 외부 소셜 서비스와 통신하는 private 헬퍼 메서드들
//    private String getAccessToken(ClientRegistration provider, String authorizationCode) {
//        // ... (WebClient를 사용한 외부 API 통신 로직) ...
//    }
//    private OAuthAttributes getUserProfile(ClientRegistration provider, String accessToken) {
//        // ... (WebClient를 사용한 외부 API 통신 로직) ...
//    }
}
