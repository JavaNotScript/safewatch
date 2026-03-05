package com.safewatch.services;

import com.safewatch.DTOs.CommentDetailsDTO;
import com.safewatch.DTOs.IncidentDTO;
import com.safewatch.DTOs.IncidentDetailsDTO;
import com.safewatch.exceptions.ConcurrentUpdateException;
import com.safewatch.exceptions.IncidentNotFoundException;
import com.safewatch.models.*;
import com.safewatch.repositories.CommentRepository;
import com.safewatch.repositories.CurrentUserRepository;
import com.safewatch.repositories.IncidentRepository;
import com.safewatch.repositories.MediaRepository;
import com.safewatch.util.HelperUtility;
import com.safewatch.util.reportRelated.IncidentModerationPolicy;
import com.safewatch.util.reportRelated.StatusTransition;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.*;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class IncidentModerationService implements IncidentModerationPolicy {
    private final IncidentRepository incidentRepository;
    private final CurrentUserRepository userRepository;
    private final CommentRepository commentRepository;
    private final MediaRepository mediaRepo;
    private final Logger logger = LoggerFactory.getLogger(IncidentModerationService.class);

    private String mask(String email) {
        return email.replaceAll("(^.).*(@.*$)", "$1***$2");
    }

    public Page<IncidentDetailsDTO> getAllReports(Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.findAll(pageable);

        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream().map(Incident::getIncidentId).toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(incident -> HelperUtility.convertToDTO(incident, mediaMap.getOrDefault(incident.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public IncidentDetailsDTO getIncidentByIncidentId(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident with id: " + incidentId + " not found"));
        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incident.getIncidentId());

        return HelperUtility.convertToDTO(incident, mediaList);
    }

    public Page<IncidentDetailsDTO> getDeletedIncidents(Pageable pageable) {
        Page<Incident> incidentPage = incidentRepository.getDeletedAtIncidents(pageable);

        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream().map(Incident::getIncidentId).toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public String deleteReportById(String adminEmail, Long reportId) {
        logger.info("Attempting to delete incident report, reportID={}, adminEmail={}", reportId, mask(adminEmail));
        User admin = userRepository.findByEmail(adminEmail).orElseThrow();

        if (!admin.hasRole(RoleType.ADMIN)) {
            logger.warn("Access denied: not an admin, userID={}", admin.getUserId());
            throw new AccessDeniedException("Not an admin");
        }

        Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + reportId + ", not found"));

        incident.setStatus(Status.REJECTED);
        incident.setReviewedBy(admin);
        incident.setReviewedAt(LocalDateTime.now());
        incident.setReviewComment("Rejected by admin");
        incidentRepository.save(incident);

        logger.info("Report Deleted: reportID={}, adminID={}", incident.getIncidentId(), admin.getUserId());
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
            Incident incident = incidentRepository.findById(reportId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + reportId + ", not found"));
            Status oldStatus = incident.getStatus();

            StatusTransition.assertAllowed(incident.getStatus(), target);

            User admin = userRepository.findByEmail(adminEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Admin not found"));


            incident.setStatus(target);
            incident.setReviewedBy(admin);
            incident.setUpdatedAt(LocalDateTime.now());
            incident.setReviewedAt(LocalDateTime.now());
            incident.setReviewComment(comment);

            logger.info("Incident transition: id={}, from={}, to={}, by={}, comment={}", incident.getIncidentId(), oldStatus, target, admin.getUserId(), comment);
            return HelperUtility.convertToDTO(incidentRepository.save(incident));
        } catch (ObjectOptimisticLockingFailureException e) {
            logger.warn("Concurrent moderation detected: reportId={}", reportId);
            throw new ConcurrentUpdateException("Report was modified by another moderator");
        }
    }

    public Page<CommentDetailsDTO> getCommentsUnderIncident(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + incidentId));

        Pageable pageable = PageRequest.of(0, 1, Sort.by("createdAt").ascending());

        Page<Comment> commentPage = commentRepository.findAllByIncident(incident.getIncidentId(), pageable);
        List<Comment> commentList = commentPage.getContent();

        if (commentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());
        }

        List<Long> commentIds = commentList.stream().map(Comment::getCommentId).toList();

        List<Media> mediaList = mediaRepo.findByCommentCommentId(commentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<CommentDetailsDTO> commentDetailsDTOList = commentList.stream().map(c -> HelperUtility.convertToDTO(c, mediaMap.getOrDefault(c.getCommentId(), List.of()))).toList();


        return new PageImpl<>(commentDetailsDTOList, pageable, commentPage.getTotalElements());
    }

    public CommentDetailsDTO getCommentByCommentId(Long commentId) {
        Comment comment = commentRepository.findById(commentId).orElseThrow(() -> new IncidentNotFoundException("Comment of id " + commentId));

        List<Media> mediaList = mediaRepo.findByCommentCommentId(comment.getCommentId());

        return HelperUtility.convertToDTO(comment, mediaList);
    }

    public Page<IncidentDetailsDTO> filterByCategory(String category, Pageable pageable) {
        IncidentCategory categoryEnum;

        try {
            categoryEnum = IncidentCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Category: " + category + " not found");
        }

        Page<Incident> incidentPage = incidentRepository.findByIncidentCategory(categoryEnum, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);
        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public Page<IncidentDetailsDTO> filterByStatus(String status, Pageable pageable) {
        Status statusEnum;

        try {
            statusEnum = Status.valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Status: " + status + " not found");
        }

        Page<Incident> incidentPage = incidentRepository.findByStatus(statusEnum, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public Page<IncidentDetailsDTO> filterBySeverity(String severity, Pageable pageable) {
        Severity severityEnum;

        try {
            severityEnum = Severity.valueOf(severity.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IncidentNotFoundException("Status: " + severity + " not found");
        }

        Page<Incident> incidentPage = incidentRepository.findBySeverity(severityEnum, pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i, mediaMap.getOrDefault(i.getIncidentId(), List.of())))
                .toList();

        return new PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public Page<IncidentDetailsDTO> getReportsByUser(Long userId, Pageable pageable) {
        User user = userRepository.findById(userId).orElseThrow(() -> new IncidentNotFoundException("User not found: " + userId));

        Page<Incident> incidentPage = incidentRepository.findByReportedByUserId(user.getUserId(),pageable);
        List<Incident> incidentList = incidentPage.getContent();

        if (incidentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, incidentPage.getTotalElements());
        }

        List<Long> incidentIds = incidentList.stream()
                .map(Incident::getIncidentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByIncidentIncidentId(incidentIds);
        Map<Long,List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<IncidentDetailsDTO> incidentDetailsDTOList = incidentList.stream()
                .map(i -> HelperUtility.convertToDTO(i,mediaMap.getOrDefault(i.getIncidentId(),List.of())))
                .toList();

        return new  PageImpl<>(incidentDetailsDTOList, pageable, incidentPage.getTotalElements());
    }

    public Page<CommentDetailsDTO> getCommentsByUser(Long userId, Pageable pageable) {
        User user = userRepository.findById(userId).orElseThrow(() -> new IncidentNotFoundException("User not found: " + userId));

        Page<Comment> commentPage = commentRepository.findByUserUserId(user.getUserId(),pageable);
        List<Comment> commentList = commentPage.getContent();

        if (commentList.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());
        }

        List<Long> commentIds = commentList.stream()
                .map(Comment::getCommentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByCommentCommentId(commentIds);
        Map<Long,List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(m -> m.getComment().getCommentId()));

        List<CommentDetailsDTO> commentDetailsDTOList = commentList.stream()
                .map(c -> HelperUtility.convertToDTO(c,mediaMap.getOrDefault(c.getCommentId(),List.of())))
                .toList();

        return new  PageImpl<>(commentDetailsDTOList, pageable, commentPage.getTotalElements());
    }
}
