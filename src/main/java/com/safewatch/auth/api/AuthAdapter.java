package com.safewatch.auth.api;

import com.safewatch.auth.internal.domain.User;
import com.safewatch.auth.internal.repo.CurrentUserRepository;
import com.safewatch.auth.internal.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
@RequiredArgsConstructor
public class AuthAdapter implements AuthFacade{
    private final CurrentUserRepository userRepository;

    @Override
    public Long extractUserId(Authentication authentication) {
            if (authentication == null || !authentication.isAuthenticated()) {
                throw new AccessDeniedException("Unauthenticated");
            }

            Object principal = authentication.getPrincipal();

            if (!(principal instanceof UserPrincipal up)) {
                throw new AccessDeniedException("Unauthenticated");
            }

            return up.getUserId();
    }

    @Override
    public String extractEmail(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Unauthenticated");
        }

        return authentication.getName();
    }

    @Override
    public User findUser(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
