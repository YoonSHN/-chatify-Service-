package com.chatify.app.core.auth.dto.response;

import com.chatify.app.core.user.domain.ImageType;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.domain.UserImage;
import com.chatify.app.core.user.domain.UserProfile;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Map;

@ToString
@Builder(access = AccessLevel.PRIVATE)
@Getter
public class OAuth2Attribute {
    private Map<String, Object> attributes;
    private String nameAttributeKey; // attributeKey -> nameAttributeKey로 이름 변경 (가독성)
    private String name;
    private String email;
    private String picture;
    private String provider;

    static OAuth2Attribute of(String provider, String nameAttributeKey,
                              Map<String, Object> attributes) {
        switch (provider) {
            case "google":
                return ofGoogle(provider, nameAttributeKey, attributes);
            case "kakao":
                return ofKakao(provider, "id", attributes); // 카카오는 id를 키로 사용
            case "naver":
                return ofNaver(provider, "id", attributes); // 네이버는 id를 키로 사용
            default:
                throw new RuntimeException("지원하지 않는 소셜 로그인입니다.");
        }
    }

    private static OAuth2Attribute ofGoogle(String provider, String nameAttributeKey,
                                            Map<String, Object> attributes) {
        return OAuth2Attribute.builder()
                .name((String) attributes.get("name")) // 이름 정보 추가
                .email((String) attributes.get("email"))
                .picture((String) attributes.get("picture")) // 프로필 사진 정보 추가
                .provider(provider)
                .attributes(attributes)
                .nameAttributeKey(nameAttributeKey)
                .build();
    }

    private static OAuth2Attribute ofKakao(String provider, String nameAttributeKey,
                                           Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuth2Attribute.builder()
                .name((String) profile.get("nickname")) // 이름 정보 추가
                .email((String) kakaoAccount.get("email"))
                .picture((String) profile.get("profile_image_url")) // 프로필 사진 정보 추가
                .provider(provider)
                .attributes(attributes) // 원본 attributes를 그대로 저장
                .nameAttributeKey(nameAttributeKey)
                .build();
    }

    private static OAuth2Attribute ofNaver(String provider, String nameAttributeKey,
                                           Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuth2Attribute.builder()
                .name((String) response.get("name")) // 이름 정보 추가
                .email((String) response.get("email"))
                .picture((String) response.get("profile_image")) // 프로필 사진 정보 추가
                .provider(provider)
                .attributes(response) // response 맵을 attributes로 사용
                .nameAttributeKey(nameAttributeKey)
                .build();
    }

    /**
     * 처음 가입하는 사용자를 위한 User 엔티티를 생성하는 메서드
     * @return User 엔티티
     */
    public User toEntity() {
        // 1. User 엔티티 생성
        User newUser = User.builder()
                .email(this.email)
                .password(null)
                .phoneNumber(null)
                .build();

        // 2. UserProfile 엔티티 생성 (이제 이미지 정보는 여기서 처리하지 않음)
        UserProfile userProfile = UserProfile.create(
                newUser,
                this.name,
                null // 생년월일 정보는 없으므로 null
        );

        // 3. UserImage 엔티티 생성
        if (this.picture != null && !this.picture.isBlank()) {
            UserImage profileImage = UserImage.create(
                    newUser,
                    this.picture,     // 소셜 플랫폼에서 가져온 프로필 사진 URL
                    ImageType.PROFILE // 이미지 타입을 PROFILE로 지정 (ImageType Enum 필요)
            );
            // 4. User와 UserImage 연결
            newUser.addUserImage(profileImage);
        }

        // 5. User와 UserProfile 연결
        newUser.setUserProfile(userProfile);

        return newUser;
    }
}