package com.safewatch.auth.internal.dto;

import com.safewatch.auth.internal.domain.RoleType;

import java.time.LocalDateTime;

public record CurrentUserDTO(
        Long userId,
        String email,
        String fName,
        String sName,
        LocalDateTime createdAt,
        RoleType roleName
) {
}
