package com.chatify.app.core.auth.service;


import com.chatify.app.core.auth.dto.request.LoginRequest;
import com.chatify.app.core.auth.dto.request.SendCodeRequest;
import com.chatify.app.core.auth.dto.request.SignupRequest;
import com.chatify.app.core.auth.dto.request.VerifyCodeRequest;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.dto.response.VerificationToken;
import jakarta.validation.Valid;

public interface AuthService {

    VerificationToken sendVerificationCode(SendCodeRequest request);

    VerificationToken verifyCode(VerifyCodeRequest request);

    void signup(SignupRequest request);

    TokenResponse login(LoginRequest loginRequest);
}
