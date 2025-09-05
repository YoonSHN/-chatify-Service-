package com.chatify.app.core.auth.repository;

import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.auth.domain.SocialAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SocialAccountRepository extends JpaRepository<SocialAccount, Long> {
    Optional<SocialAccount> findByProviderAndProviderUserId(Provider provider, String providerUserId);
}
