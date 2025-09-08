package com.chatify.app.core.auth.dto.response;

import com.chatify.app.core.auth.domain.Provider;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

import static com.chatify.app.core.auth.domain.Provider.*;

@Getter
@Builder
public class OAuthAttributes {
    private String providerUserId;
    private Provider provider;
    private String email;
    private String name;

    public static OAuthAttributes of(Provider providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case GOOGLE:
                return ofGoogle(attributes);
            case KAKAO:
                return ofKakao(attributes);
            case NAVER:
                return ofNaver(attributes);
            default:
                throw new IllegalArgumentException("지원하지 않는 소셜 로그인입니다: " + providerType);
        }
    }

    private static OAuthAttributes ofGoogle(Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .providerUserId((String) attributes.get("sub"))
                .provider(Provider.GOOGLE)
                .email((String) attributes.get("email"))
                .name((String) attributes.get("name"))
                .build();
    }

    private static OAuthAttributes ofKakao(Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuthAttributes.builder()
                .providerUserId(String.valueOf(attributes.get("id")))
                .provider(Provider.KAKAO)
                .email((String) kakaoAccount.get("email"))
                .name((String) kakaoProfile.get("nickname"))
                .build();
    }

    private static OAuthAttributes ofNaver(Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuthAttributes.builder()
                .providerUserId((String) response.get("id"))
                .provider(Provider.NAVER)
                .email((String) response.get("email"))
                .name((String) response.get("name"))
                .build();
    }
}