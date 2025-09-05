package com.chatify.app.core.auth.service;

import com.chatify.app.core.auth.domain.Provider;
import com.chatify.app.core.auth.dto.response.OAuthAttributes;
import com.chatify.app.core.auth.dto.response.TokenResponse;
import com.chatify.app.core.user.domain.User;

public interface OAuth2Service {
    TokenResponse socialLogin(Provider provider, String authorizationCode);

}
