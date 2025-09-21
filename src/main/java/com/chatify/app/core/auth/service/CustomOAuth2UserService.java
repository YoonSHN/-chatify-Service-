package com.chatify.app.core.auth.service; // 실제 패키지 경로

import com.chatify.app.core.auth.dto.response.OAuth2Attribute; // OAuthAttributes -> OAuthAttribute
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

        // 2. 현재 로그인 진행 중인 서비스를 구분합니다.
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 3. OAuth2 로그인 시 키가 되는 필드 값을 가져옵니다.
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // 4. 소셜 로그인별 특성을 처리하는 DTO(OAuthAttribute)를 생성합니다.
        OAuth2Attribute attributes = OAuth2Attribute.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 5. 이메일을 기준으로 DB에서 사용자를 찾아, 없으면 새로 저장(가입), 있으면 정보를 업데이트합니다.
        User user = saveOrUpdate(attributes);

        // 6. 사용자의 정보와 권한을 담아 DefaultOAuth2User 객체를 생성하여 반환합니다.
        //    이 객체는 이후 SuccessHandler에서 사용됩니다.
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                attributes.getAttributes(),
                attributes.getNameAttributeKey());
    }

    /**
     * OAuthAttribute DTO를 받아 DB에 사용자를 저장하거나 업데이트합니다.
     * @param attributes 소셜 플랫폼에서 받아온 사용자 정보 DTO
     * @return DB에 저장되거나 업데이트된 User 엔티티
     */
    private User saveOrUpdate(OAuth2Attribute attributes) {
        User user = userRepository.findUserByEmail(attributes.getEmail())
                // 이미 가입된 사용자라면, 이름 정보만 업데이트
                .map(entity -> entity.updateSocialProfile(attributes.getName()))
                // 가입되지 않은 사용자라면, DTO를 엔티티로 변환하여 새로 생성
                .orElse(attributes.toEntity());

        return userRepository.save(user);
    }
}