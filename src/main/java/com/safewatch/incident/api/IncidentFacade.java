package com.safewatch.incident.api;

import com.safewatch.common.domain.IncidentCategory;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.domain.Status;
import com.safewatch.incident.internal.dto.IncidentDTO;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IncidentFacade {
    IncidentDetailsDTO findById(Long incidentId);

    Page<IncidentDetailsDTO> findAll(Pageable pageable);

    void deleteReport(Long reportId, Long adminId);

    void updateIncidentTransition(Long reportId, Status target, Long aLong, String comment);

    Page<IncidentDetailsDTO> findByUserId(Long userId, Pageable pageable);

    Page<IncidentDetailsDTO> getDeletedIncidents(Pageable pageable);

    Page<IncidentDetailsDTO> filterByCategory(IncidentCategory category, Pageable pageable);

    Page<IncidentDetailsDTO> filterByStatus(Status status, Pageable pageable);

    Page<IncidentDetailsDTO> filterBySeverity(Severity severity, Pageable pageable);

    IncidentDetailsDTO getIncidentReportedBy(Long userId, Long incidentId);

    IncidentDTO getByIncidentId(Long reportId);
}
