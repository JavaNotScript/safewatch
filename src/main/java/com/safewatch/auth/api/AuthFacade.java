package com.safewatch.auth.api;

import com.safewatch.auth.internal.domain.User;
import org.springframework.security.core.Authentication;

public interface AuthFacade {
    Long extractUserId(Authentication authentication);
    String extractEmail(Authentication authentication);
    User findUser(String email);
}
