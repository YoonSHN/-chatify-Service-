package com.chatify.app.core.auth.service;

import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.auth.domain.SocialAccount;
import com.chatify.app.core.auth.dto.response.OAuthAttributes;
import com.chatify.app.core.auth.repository.SocialAccountRepository;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. 기본 OAuth2UserService를 사용하여 사용자 정보를 로드합니다.
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 2. 현재 로그인 진행 중인 서비스를 구분하는 ID를 가져옵니다 (예: google, naver, kakao).
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // 3. OAuth2 로그인 진행 시 키가 되는 필드값 (Primary Key와 같은 의미)을 가져옵니다.
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // 4. OAuth2UserService를 통해 가져온 OAuth2User의 attribute를 담을 클래스입니다.
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 5. 사용자 조회 또는 신규 가입 처리
        User user = findOrCreateUser(attributes);

        // 6. Spring Security가 인식할 수 있는 OAuth2User 객체를 반환합니다.
        // 여기에는 사용자 정보, 권한, 그리고 SuccessHandler에서 사용할 추가 속성을 담습니다.
        Map<String, Object> customAttributes = attributes.getAttributes();
        customAttributes.put("userId", user.getId()); // SuccessHandler에서 사용할 수 있도록 유저 ID 추가

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                customAttributes,
                attributes.getNameAttributeKey());
    }

    private User findOrCreateUser(OAuthAttributes attributes) {
        // 소셜 계정 정보로 이미 가입된 사용자인지 확인
        Optional<SocialAccount> socialAccountOptional = socialAccountRepository.findByProviderAndProviderUserId(
                attributes.getProvider(),
                attributes.getAttributes().get(attributes.getNameAttributeKey()).toString()
        );
        if (socialAccountOptional.isPresent()) {
            return socialAccountOptional.get().getUser();
        }

        // 이메일로 이미 가입된 사용자인지 확인
        Optional<User> userOptional = userRepository.findUserByEmail(attributes.getEmail());
        if (userOptional.isPresent()) {
            // 이미 존재하는 유저라면, 새로운 소셜 계정 정보를 연결해줍니다.
            User existingUser = userOptional.get();
            connectSocialAccount(existingUser, attributes);
            return existingUser;
        }

        // 신규 사용자라면, 새로 생성합니다.
        User newUser = attributes.toEntity();
        userRepository.save(newUser);
        connectSocialAccount(newUser, attributes);
        return newUser;
    }

    private void connectSocialAccount(User user, OAuthAttributes attributes) {
        String providerUserId = attributes.getAttributes().get(attributes.getNameAttributeKey()).toString();
        SocialAccount socialAccount = SocialAccount.create(user, attributes.getProvider(), providerUserId);
        socialAccountRepository.save(socialAccount);
    }
}
