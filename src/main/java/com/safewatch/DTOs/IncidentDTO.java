package com.safewatch.DTOs;

import com.safewatch.models.Incident;
import com.safewatch.models.IncidentCategory;
import com.safewatch.models.Severity;
import com.safewatch.models.Status;

import java.time.LocalDateTime;

public record IncidentDTO(
        Long incidentId,
        String title,
        String location,
        double longitude,
        double latitude,
        Severity severity,
        IncidentCategory incidentCategory,
        Status status,
        long version,
        LocalDateTime reportedAt) {
    public static IncidentDTO from(Incident i) {
        return new IncidentDTO(i.getIncidentId(), i.getTitle(), i.getLocation(),i.getLongitude(),i.getLatitude(), i.getSeverity(), i.getIncidentCategory(), i.getStatus(), i.getVersion(), i.getReportedAt());
    }

}
