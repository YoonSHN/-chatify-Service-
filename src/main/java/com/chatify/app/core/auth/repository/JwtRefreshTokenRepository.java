package com.chatify.app.core.auth.repository;

import com.chatify.app.core.auth.domain.JwtRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JwtRefreshTokenRepository extends JpaRepository<JwtRefreshToken, Long> {
}

