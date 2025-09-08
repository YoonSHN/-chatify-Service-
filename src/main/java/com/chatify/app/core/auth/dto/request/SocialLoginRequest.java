package com.chatify.app.core.auth.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class SocialLoginRequest {
    private String authorizationCode;
}
