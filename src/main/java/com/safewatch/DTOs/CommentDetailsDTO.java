package com.safewatch.DTOs;

import java.time.OffsetDateTime;
import java.util.List;

public record CommentDetailsDTO(
        Long commentId,
        String comment,
        Long userId,
        Long incidentId,
        OffsetDateTime createAt,
        List<MediaDTO> media
) {
}
