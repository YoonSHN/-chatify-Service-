package com.chatify.app.core.auth.service.impl;

import com.chatify.app.core.auth.dto.response.OAuthAttributes;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. 기본 OAuth2UserService를 통해 OAuth2User 객체를 받아옵니다.
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 2. 현재 로그인 진행 중인 서비스를 구분합니다. (예: google, naver, kakao)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 3. OAuth2 로그인 시 키가 되는 필드 값(Primary Key)을 가져옵니다.
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // 4. OAuth2UserService를 통해 가져온 OAuth2User의 attribute를 담을 DTO를 생성합니다.
        //    (올려주신 OAuthAttributes 클래스 활용)
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 5. 이메일을 기준으로 DB에서 사용자를 찾아, 없으면 새로 저장(가입), 있으면 정보를 업데이트합니다.
        User user = saveOrUpdate(attributes);

        // 6. Spring Security가 인식할 수 있는 인증 객체를 생성하여 반환합니다.
        //    세션에 사용자 정보를 저장하기 위한 DTO라고 생각하면 편리합니다.
        //    여기서는 사용자의 이메일과 권한, 그리고 소셜 플랫폼에서 받은 원본 속성을 담아 반환합니다.
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")), // 우선 기본 권한 부여
                attributes.getAttributes(),
                attributes.getNameAttributeKey());
    }

    /**
     * OAuthAttributes DTO를 받아 DB에 사용자를 저장하거나 업데이트합니다.
     * @param attributes 소셜 플랫폼에서 받아온 사용자 정보 DTO
     * @return DB에 저장되거나 업데이트된 User 엔티티
     */
    private User saveOrUpdate(OAuthAttributes attributes) {
        User user = userRepository.findUserByEmail(attributes.getEmail())
                // 이미 가입된 사용자라면, 이름 정보만 업데이트 (프로필 사진 등도 추가 가능)
                .map(entity -> entity.updateSocialProfile(attributes.getName()))
                // 가입되지 않은 사용자라면, DTO를 엔티티로 변환하여 새로 생성
                .orElse(attributes.toEntity());

        return userRepository.save(user);
    }
}