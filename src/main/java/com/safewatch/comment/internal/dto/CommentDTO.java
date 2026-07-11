package com.safewatch.comment.internal.dto;

import java.time.OffsetDateTime;

public record CommentDTO(
        Long commentId,
        String comment,
        Long userId,
        Long incidentId,
        OffsetDateTime createAt
) {
}
