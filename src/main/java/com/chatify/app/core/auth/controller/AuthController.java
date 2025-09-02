package com.chatify.app.core.auth.controller;

import com.chatify.app.core.auth.dto.request.LoginRequest;
import com.chatify.app.core.auth.dto.request.SendCodeRequest;
import com.chatify.app.core.auth.dto.request.SignupRequest;

import com.chatify.app.core.auth.dto.request.VerifyCodeRequest;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.dto.response.VerificationToken;
import com.chatify.app.core.auth.service.AuthService;
import com.chatify.app.common.response.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    //1. 인증 번호 발송 + 임시 인증 토큰(A) 발급 (인증 대기중)
    @PostMapping("/send-verification-code")
    public ResponseEntity<ApiResponse<VerificationToken>> sendVerificationCode(@Valid @RequestBody SendCodeRequest request){
        VerificationToken response = authService.sendVerificationCode(request);
        return ResponseEntity.status(HttpStatus.OK)
                .body(ApiResponse.success(HttpStatus.OK, "인증번호가 성공적으로 발송되었습니다.", response));
    }
    //2. 인증 번호 확인 및 임시 인증 토큰(B) 발급 (인증 성공)
    @PostMapping("/verify-code")
    public ResponseEntity<ApiResponse<VerificationToken>> verifyCode(@Valid @RequestBody VerifyCodeRequest request){
        VerificationToken response = authService.verifyCode(request);

        return ResponseEntity.status(HttpStatus.OK)
                .body(ApiResponse.success(HttpStatus.OK, "이메일 인증이 성공적으로 완료되었습니다.", response));

    }
    //3. 회원가입 완료
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@Valid @ModelAttribute SignupRequest signupRequest){
        authService.signup(signupRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(HttpStatus.CREATED, "회원가입이 정상적으로 완료되었습니다."));
    }

        /*
    로그인
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        TokenResponse response = authService.login(loginRequest);
        return ResponseEntity.status(HttpStatus.OK)
                .body(ApiResponse.success(HttpStatus.OK, "로그인에 성공했습니다.", response));
    }
    /*
    소셜 로그인 -> db에 회원이 존재하는지 검사 -> 있으면 소셜로그인 테이블만 추가,없으면 유저, 소셜 테이블 추가
     */
//    @PostMapping("/social-login")
//    public ResponseEntity<ApiResponse<>>

}
