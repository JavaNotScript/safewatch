package com.safewatch.incident.internal.repo;

import com.safewatch.incident.internal.domain.Incident;
import com.safewatch.common.domain.IncidentCategory;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.domain.Status;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    @Query("SELECT i FROM Incident i WHERE i.status = :status AND i.deletedAt IS NULL")
    Page<Incident> findAllVisibleReports(Status status, Pageable pageable);

    Page<Incident> findByIncidentCategoryAndStatusAndDeletedAtIsNull(IncidentCategory category, Status status, Pageable pageable);

    @Query("SELECT i FROM Incident i WHERE i.reportedBy = :userId AND i.status = :status AND i.deletedAt IS NULL")
    Page<Incident> findByReportedByAndDeletedAtIsNull(Long userId, Status status, Pageable pageable);

    Page<Incident> findBySeverityAndStatusAndDeletedAtIsNull(Severity severity, Status status, Pageable pageable);

    @Query("SELECT i FROM Incident i WHERE i.incidentId = :incidentId AND i.status = :status AND i.deletedAt IS NULL")
    Optional<Incident> findVisibleReportBy(@Param("incidentId") Long incidentId, Status status);

    @Query("SELECT i FROM Incident i WHERE i.reportedBy = :userId AND i.deletedAt IS NULL")
    Page<Incident> getMyVisibleReports(@Param("userId") Long userId, Pageable pageable);

    @Query("SELECT i FROM Incident i WHERE i.deletedAt IS NOT NULL")
    Page<Incident> getDeletedAtIncidents(Pageable pageable);

    Page<Incident> findByIncidentCategory(IncidentCategory categoryEnum, Pageable pageable);

    Page<Incident> findByStatus(Status statusEnum, Pageable pageable);

    Page<Incident> findBySeverity(Severity severityEnum, Pageable pageable);

    Page<Incident> findByReportedBy(Long userId, Pageable pageable);
}
