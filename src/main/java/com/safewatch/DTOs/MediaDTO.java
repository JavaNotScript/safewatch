package com.safewatch.DTOs;

import java.time.OffsetDateTime;
import java.util.UUID;

public record MediaDTO(
        UUID mediaId,
        String originalFilename,
        String contentType,
        long sizeBytes,
        OffsetDateTime createdAt
        //,String url
) {
}
