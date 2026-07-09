package com.safewatch.auth.internal.security;

import com.safewatch.auth.internal.domain.User;
import com.safewatch.auth.internal.repo.CurrentUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
    private final CurrentUserRepository currentUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = currentUserRepository.findByEmail(username).orElseThrow();

        return new UserPrincipal(user);
    }
}
