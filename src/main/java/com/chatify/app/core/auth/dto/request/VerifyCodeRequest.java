package com.chatify.app.core.auth.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifyCodeRequest {

    private String email;
    private String code;
}
