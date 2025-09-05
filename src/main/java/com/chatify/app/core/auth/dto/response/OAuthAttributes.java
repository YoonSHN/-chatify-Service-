package com.chatify.app.core.auth.dto.response;

import com.chatify.app.core.auth.domain.Provider;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
@Builder
public class OAuthAttributes {
    private String providerUserId;
    private Provider provider;
    private String email;
    private String name;

    public static OAuthAttributes ofProvider(String providerUserId, Provider provider, Map<String, Object> attributes){
        return OAuthAttributes.builder()
                .providerUserId(providerUserId)
                .provider(provider)
                .email((String)attributes.get("email"))
                .name((String)attributes.get("name"))
                .build();
    }
}
