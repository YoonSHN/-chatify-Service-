package com.chatify.app.core.auth.dto.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class VerificationToken {

    private String verificationToken;
}
