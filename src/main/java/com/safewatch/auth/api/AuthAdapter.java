package com.safewatch.auth.api;

import com.safewatch.auth.internal.domain.User;
import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.auth.internal.dto.UserDTO;
import com.safewatch.auth.internal.repo.CurrentUserRepository;
import com.safewatch.auth.internal.security.UserPrincipal;
import com.safewatch.common.util.HelperUtility;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    public CurrentUserDTO findUser(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        return HelperUtility.convertToDTO(user);
    }

    @Override
    public UserDTO findByUserId(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("User not found."));

        return new UserDTO(
                user.getEmail(),
                user.isLocked(),
                user.isEnabled(),
                user.isCredentialsExpired()
        );
    }

    @Override
    public CurrentUserDTO findUserByUserId(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("User not found."));

        return HelperUtility.convertToDTO(user);
    }
}
