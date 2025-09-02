package com.chatify.app.core.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SendCodeRequest {

    @NotBlank
    private String email;


}
