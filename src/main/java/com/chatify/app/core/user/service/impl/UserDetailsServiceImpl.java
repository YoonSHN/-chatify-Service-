package com.chatify.app.core.user.service.impl;

import com.chatify.app.core.user.repository.UserRepository;
import com.chatify.app.core.user.service.UserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service // 이 클래스를 Spring Bean으로 등록합니다.
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // email로 DB에서 사용자를 찾습니다.
        return userRepository.findUserByEmail(email)
                // 사용자를 찾지 못하면 예외를 던집니다.
                .orElseThrow(() -> new UsernameNotFoundException(email + "을 찾을 수 없습니다."));
    }
}
