package com.chatify.app.core.auth.dto.response;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Setter
public class TokenResponse { //로그인 성공시 발급 되는 토큰들
    private String accessToken;
    private String refreshToken;
}
