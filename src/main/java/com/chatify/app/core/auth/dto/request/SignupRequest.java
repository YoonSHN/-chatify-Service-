package com.chatify.app.core.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@NoArgsConstructor
public class SignupRequest {

    @NotBlank(message = "비밀번호는 필수 입력값 입니다.")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,16}$",
            message = "비밀번호는 8~16자 영문, 숫자, 특수문자를 포함해야 합니다.")
    private String password;
    @Size(min=2, max=50, message="이름은 2자 이상 50자 이하로 입력해주세요.")
    @NotBlank(message = "이름은 필수 입력값 입니다.")
    private String realName;

    @NotNull(message = "생년월일은 필수 입력 값입니다.")
    @Past(message = "생년월일은 현재 날짜보다 이전이어야 합니다.")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
    private LocalDate birthday;

    @NotBlank(message="전화번호는 필수 입력 값입니다.")
    @Pattern(regexp = "^010-\\d{4}-\\d{4}$", message = "전화번호 형식이 올바르지 않습니다. (010-XXXX-XXXX)")
    private String phoneNumber;

    @NotBlank(message="인증 토큰은 필수입니다.")
    private String verificationToken;
}
