package com.chatify.app.core.auth.dto.response;

import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.domain.UserProfile;
import com.chatify.app.core.user.domain.UserSettings;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Map;

/**
 * 소셜 플랫폼에서 가져온 사용자 정보의 속성을 담는 통일된 DTO 입니다.
 */
@ToString
@Builder(access = AccessLevel.PRIVATE)
@Getter
public class OAuthAttributes {

    private Map<String, Object> attributes; // 원본 사용자 속성 정보
    private String nameAttributeKey;        // 사용자 이름 속성의 키 (예: "sub", "id")
    private String name;                    // 사용자 이름
    private String email;                   // 사용자 이메일
    private Provider provider;              // 소셜 플랫폼 제공자

    /**
     * provider 이름과 사용자 속성을 기반으로 적절한 OAuthAttributes 객체를 생성합니다.
     */
    public static OAuthAttributes of(String registrationId, String userNameAttributeName, Map<String, Object> attributes) {
        String providerName = registrationId.toUpperCase();
        switch (providerName) {
            case "NAVER":
                return ofNaver(userNameAttributeName, attributes);
            case "KAKAO":
                return ofKakao(userNameAttributeName, attributes);
            default: // GOOGLE 및 기타
                return ofGoogle(userNameAttributeName, attributes);
        }
    }

    private static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .name((String) attributes.get("name"))
                .email((String) attributes.get("email"))
                .provider(Provider.GOOGLE)
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuthAttributes.builder()
                .name((String) profile.get("nickname"))
                .email((String) kakaoAccount.get("email"))
                .provider(Provider.KAKAO)
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    private static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuthAttributes.builder()
                .name((String) response.get("name"))
                .email((String) response.get("email"))
                .provider(Provider.NAVER)
                .attributes(attributes)
                .nameAttributeKey(userNameAttributeName)
                .build();
    }

    /**
     * 처음 가입하는 사용자를 위한 User 엔티티를 생성합니다.
     */
    public User toEntity() {
        User newUser = User.builder()
                .email(this.email)
                .password(null) // 소셜 로그인은 비밀번호가 없음
                .build();

        UserProfile userProfile = UserProfile.create(newUser, this.name, null);
        UserSettings userSettings = UserSettings.create(newUser);
        newUser.setUserProfile(userProfile);
        newUser.setUserSettings(userSettings);

        return newUser;
    }
}