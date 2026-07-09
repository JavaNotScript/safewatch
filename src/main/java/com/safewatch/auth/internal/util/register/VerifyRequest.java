package com.safewatch.auth.internal.util.register;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequest(@NotBlank String token) {
}
