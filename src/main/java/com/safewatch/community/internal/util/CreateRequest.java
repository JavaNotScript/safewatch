package com.safewatch.community.internal.util;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateRequest(
        @NotBlank @Size(min = 5,max = 20) String communityName,
        @NotBlank String communityAudience,
        @NotBlank String communityVisibility
) {
}
