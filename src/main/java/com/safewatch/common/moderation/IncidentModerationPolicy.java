package com.safewatch.common.moderation;

import com.safewatch.incident.internal.dto.IncidentDTO;

public interface IncidentModerationPolicy {

    IncidentDTO verifyIncident(String adminEmail, Long id);

    IncidentDTO publishIncident(Long id, String adminEmail);

    IncidentDTO rejectIncident(Long id, String adminEmail, String reason);

    IncidentDTO flagIncident(Long id, String adminEmail, String reason);

}
