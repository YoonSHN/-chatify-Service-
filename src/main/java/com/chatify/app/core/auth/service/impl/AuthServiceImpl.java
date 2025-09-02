package com.chatify.app.core.auth.service.impl;

import com.chatify.app.core.auth.dto.request.LoginRequest;
import com.chatify.app.core.auth.dto.request.SendCodeRequest;
import com.chatify.app.core.auth.dto.request.SignupRequest;
import com.chatify.app.core.auth.dto.request.VerifyCodeRequest;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.auth.dto.response.VerificationToken;
import com.chatify.app.core.auth.service.AuthService;
import com.chatify.app.core.auth.service.EmailService;
import com.chatify.app.core.user.domain.User;
import com.chatify.app.core.user.domain.UserProfile;
import com.chatify.app.core.user.domain.UserSettings;
import com.chatify.app.core.user.repository.UserRepository;
import com.chatify.app.common.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final StringRedisTemplate redisTemplate;

    private static final String VERIFICATION_CODE_PREFIX = "verify:code=>";

    //이메일로 인증번호 보내고 임시 인증 토큰 받기
    @Override
    public VerificationToken sendVerificationCode(SendCodeRequest request) {
        //6자리 인증번호 발급
        String code = String.format("%06d", new Random().nextInt(999999));

        //redis에 인증번호 저장(검사용)
        redisTemplate.opsForValue().set(VERIFICATION_CODE_PREFIX + request.getEmail(), code, Duration.ofMinutes(3));

        //이메일 발송
        emailService.sendMail(request.getEmail(), "Chatify 회원가입 인증번호", "인증번호: " + code);


        //"인증 대기중" 상태의 토큰 생성 및 반환 (유효 기간 5분)
        String pendingToken = jwtUtil.createPendingToken(request.getEmail());
        return new VerificationToken(pendingToken);
    }

    @Override
    public VerificationToken verifyCode(VerifyCodeRequest request) {
        //redis에서 이메일로 인증번호 조회
        String storedCode = redisTemplate.opsForValue().get(VERIFICATION_CODE_PREFIX + request.getEmail());

        //인증번호 비교
        if (!(storedCode != null && storedCode.equals(request.getCode()))) {
            throw new IllegalArgumentException("인증 번호가 일치하지 않습니다..");
        }

        //인증 성공 시 Redis에서 번호 삭제
        redisTemplate.delete(VERIFICATION_CODE_PREFIX + request.getEmail());

        //인증 성공 토큰 발급 (유효 기간 30분)
        String successToken = jwtUtil.createSuccessToken(request.getEmail());
        return new VerificationToken(successToken);
    }

    /*
    자체 회원 가입
     */
    @Override
    @Transactional
    public void signup(SignupRequest signupRequest) {

        //인증 성공 토큰 검증 (유효 한지, success 가 있는지)
        String email = jwtUtil.validateAndGetEmail(signupRequest.getVerificationToken(), "SUCCESS");

        if (userRepository.existsUserByEmail(email)) {
            throw new IllegalArgumentException("이미 가입된 이메일입니다.");
        }
        User user = User.builder().
                email(email).
                password(passwordEncoder.encode(signupRequest.getPassword())).
                phoneNumber(signupRequest.getPhoneNumber()).build();

        UserProfile userProfile = UserProfile.create(user,
                signupRequest.getRealName(), signupRequest.getBirthday());

        UserSettings userSettings = UserSettings.create(user);

        // 객체 양쪽값 모두 저장
        user.setUserProfile(userProfile);
        user.setUserSettings(userSettings);

        userRepository.save(user);
    }

    @Override
    @Transactional
    public TokenResponse login(LoginRequest loginRequest){
        return new TokenResponse("1","1");

    }


}
