package com.safewatch.auth.internal.util.login;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 8) String newPassword,
        @NotBlank String confirmPassword
) {
}
