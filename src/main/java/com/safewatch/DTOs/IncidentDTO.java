package com.safewatch.DTOs;

import com.safewatch.models.Incident;
import com.safewatch.models.IncidentCategory;
import com.safewatch.models.Severity;
import com.safewatch.models.Status;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

public record IncidentDTO(
        Long incidentId,
        String title,
        String location,
        Severity severity,
        IncidentCategory incidentCategory,
        Status status,
        long version,
        LocalDateTime reportedAt) {
    public static IncidentDTO from(Incident i) {
        return new IncidentDTO(i.getIncidentId(),i.getTitle(), i.getLocation(), i.getSeverity(), i.getIncidentCategory(), i.getStatus(), i.getVersion(),i.getReportedAt());
    }

}
