package com.safewatch.common.moderation;

import com.safewatch.auth.api.AuthFacade;
import com.safewatch.auth.internal.domain.RoleType;
import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.comment.api.CommentFacade;
import com.safewatch.comment.internal.dto.CommentDTO;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.common.domain.IncidentCategory;
import com.safewatch.common.domain.Media;
import com.safewatch.common.exceptions.ConcurrentUpdateException;
import com.safewatch.common.exceptions.IncidentNotFoundException;
import com.safewatch.common.util.HelperUtility;
import com.safewatch.incident.api.IncidentFacade;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.domain.Status;
import com.safewatch.incident.internal.dto.IncidentDTO;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import com.safewatch.common.util.StatusTransition;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class ModerationService implements IncidentModerationPolicy {
    private final IncidentFacade incidentFacade;
    private final AuthFacade authFacade;
    private final CommentFacade commentFacade;
    private final MediaRepository mediaRepo;
    private final Logger logger = LoggerFactory.getLogger(ModerationService.class);

    private String mask(String email) {
        return email.replaceAll("(^.).*(@.*$)", "$1***$2");
    }

    public Page<IncidentDetailsDTO> getAllReports(Pageable pageable) {
        return incidentFacade.findAll(pageable);
    }

    public IncidentDetailsDTO getIncidentByIncidentId(Long incidentId) {
        return incidentFacade.findById(incidentId);
    }

    public Page<IncidentDetailsDTO> getDeletedIncidents(Pageable pageable) {
        return incidentFacade.getDeletedIncidents(pageable);
    }

    public String deleteReportById(String adminEmail, Long reportId) {
        logger.info("Attempting to delete incident report, reportID={}, adminEmail={}", reportId, mask(adminEmail));
        CurrentUserDTO admin = authFacade.findUser(adminEmail);

        if (!admin.roleName().equals(RoleType.ADMIN)) {
            logger.warn("Access denied: not an admin, userID={}", admin.userId());
            throw new AccessDeniedException("Not an admin");
        }

        incidentFacade.deleteReport(reportId, admin.userId());
        return "report rejected.";
    }

    @Override
    public IncidentDTO verifyIncident(String adminEmail, Long id) {
        logger.info("Verifying incident report: report={},adminEmail={}", id, mask(adminEmail));
        return transition(id, adminEmail, Status.VERIFIED, null);
    }

    @Override
    public IncidentDTO publishIncident(Long id, String adminEmail) {
        logger.info("Publishing incident report: report={},adminEmail={}", id, mask(adminEmail));
        return transition(id, adminEmail, Status.PUBLISHED, null);
    }

    @Override
    public IncidentDTO rejectIncident(Long id, String adminEmail, String reason) {
        logger.info("Rejecting incident report: report={},adminEmail={}, reason={}", id, mask(adminEmail), reason);
        return transition(id, adminEmail, Status.REJECTED, reason);
    }

    @Override
    public IncidentDTO flagIncident(Long id, String adminEmail, String reason) {
        logger.info("Flagging incident report: report={},adminEmail={}, reason={}", id, mask(adminEmail), reason);
        return transition(id, adminEmail, Status.FLAGGED, reason);
    }

    private IncidentDTO transition(Long reportId, String adminEmail, Status target, String comment) {
        try {
            IncidentDTO incident = incidentFacade.getByIncidentId(reportId);
            Status oldStatus = incident.status();

            StatusTransition.assertAllowed(incident.status(), target);

            CurrentUserDTO admin = authFacade.findUser(adminEmail);
            incidentFacade.updateIncidentTransition(reportId, target, admin.userId(), comment);

            logger.info("Incident transition: id={}, from={}, to={}, by={}, comment={}", incident.incidentId(), oldStatus, target, admin.userId(), comment);
            return incident;
        } catch (ObjectOptimisticLockingFailureException e) {
            logger.warn("Concurrent moderation detected: reportId={}", reportId);
            throw new ConcurrentUpdateException("Report was modified by another moderator");
        }
    }


    /// //////////////////////////////////////////////
    public Page<CommentDetailsDTO> getCommentsUnderIncident(Long incidentId) {
        IncidentDetailsDTO incident = incidentFacade.findById(incidentId);

        Pageable pageable = PageRequest.of(0, 1, Sort.by("createdAt").ascending());
        return commentFacade.getCommentsByIncident(incident.incidentId(), pageable);
    }

    public CommentDetailsDTO getCommentByCommentId(Long commentId) {
        CommentDTO comment = commentFacade.findByCommentId(commentId);

        List<Media> mediaList = mediaRepo.findByCommentId(comment.commentId());

        return HelperUtility.convertToDTO(comment, mediaList);
    }

    public Page<IncidentDetailsDTO> filterByCategory(String category, Pageable pageable) {
        IncidentCategory categoryEnum;

        try {
            categoryEnum = IncidentCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Category: " + category + " not found");
        }

        return incidentFacade.filterByCategory(categoryEnum, pageable);
    }

    public Page<IncidentDetailsDTO> filterByStatus(String status, Pageable pageable) {
        Status statusEnum;

        try {
            statusEnum = Status.valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Status: " + status + " not found");
        }

        return incidentFacade.filterByStatus(statusEnum, pageable);
    }

    public Page<IncidentDetailsDTO> filterBySeverity(String severity, Pageable pageable) {
        Severity severityEnum;

        try {
            severityEnum = Severity.valueOf(severity.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Status: " + severity + " not found");
        }

        return incidentFacade.filterBySeverity(severityEnum, pageable);
    }

    public Page<IncidentDetailsDTO> getReportsByUser(Long userId, Pageable pageable) {
        CurrentUserDTO user = authFacade.findUserByUserId(userId);

        return incidentFacade.findByUserId(user.userId(), pageable);
    }

    public Page<CommentDetailsDTO> getCommentsByUser(Long userId, Pageable pageable) {
        CurrentUserDTO user = authFacade.findUserByUserId(userId);

        return commentFacade.findByUserUserId(user.userId(), pageable);
    }

    public IncidentDetailsDTO getIncidentReportedBy(Long userId, Long incidentId) {
        CurrentUserDTO user = authFacade.findUserByUserId(userId);

        return incidentFacade.getIncidentReportedBy(user.userId(),incidentId);
    }

    public CommentDetailsDTO getCommentIncidentId(Long commentId, Long userId) {
        CurrentUserDTO user = authFacade.findUserByUserId(userId);

        CommentDTO comment = commentFacade.findByCommentId(commentId);

        if (!comment.userId().equals(user.userId())) {
            throw new IncidentNotFoundException("comment not found");
        }

        List<Media> mediaList = mediaRepo.findByCommentId(comment.commentId());

        return HelperUtility.convertToDTO(comment, mediaList);
    }
}
