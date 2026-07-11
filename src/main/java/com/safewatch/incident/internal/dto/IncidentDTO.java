package com.safewatch.incident.internal.dto;

import com.safewatch.common.domain.IncidentCategory;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.domain.Status;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;

public record IncidentDTO(
        Long incidentId,
        Long reportedBy,
        String title,
        String description,
        String location,
        Severity severity,
        IncidentCategory incidentCategory,
        Status status,
        long version,
        LocalDateTime reportedAt,
        OffsetDateTime deletedAt
) {

}
