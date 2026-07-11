package com.safewatch.comment.internal.util;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CommentRequest(@NotBlank @Size(min = 10, max = 400) String description) {
}
