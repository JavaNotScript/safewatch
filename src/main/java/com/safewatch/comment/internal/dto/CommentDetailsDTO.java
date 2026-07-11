package com.safewatch.comment.internal.dto;

import com.safewatch.common.dto.MediaDTO;

import java.time.OffsetDateTime;
import java.util.List;

public record CommentDetailsDTO(
        Long commentId,
        String comment,
        Long userId,
        Long incidentId,
        OffsetDateTime createdAt,
        List<MediaDTO> media
) {
}
