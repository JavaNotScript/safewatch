package com.safewatch.DTOs;

import com.safewatch.models.IncidentCategory;
import com.safewatch.models.Severity;
import com.safewatch.models.Status;

import java.time.LocalDateTime;
import java.util.List;

public record IncidentDetailsDTO(
        Long incidentId,
        String title,
        String description,
        String location,
        Severity severity,
        IncidentCategory incidentCategory,
        Status status,
        long version,
        LocalDateTime reportedAt,
        List<MediaDTO> media
) {
}
