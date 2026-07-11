package com.safewatch.auth.api;

import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.auth.internal.dto.UserDTO;
import org.springframework.security.core.Authentication;

public interface AuthFacade {
    Long extractUserId(Authentication authentication);
    String extractEmail(Authentication authentication);
    CurrentUserDTO findUser(String email);
    UserDTO findByUserId(Long userId);
    CurrentUserDTO findUserByUserId(Long userId);
}
