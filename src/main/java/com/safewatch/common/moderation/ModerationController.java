package com.safewatch.common.moderation;

import com.safewatch.auth.api.AuthFacade;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.incident.internal.dto.IncidentDTO;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class ModerationController {
    private final ModerationService incidentModerationService;
    private final AuthFacade authFacade;
    private final Logger logger = LoggerFactory.getLogger(ModerationController.class);
    //re-assigning roles -> user-moderator when certain requirements are met -> send an alert to admin email

    @GetMapping("/get-all")
    public ResponseEntity<Page<IncidentDetailsDTO>> getAllIncidents(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.getAllReports(pageable));
    }

    @GetMapping("/get/{incidentId}")
    public ResponseEntity<IncidentDetailsDTO> getIncidentByIncidentId(@PathVariable("incidentId") Long incidentId) {
        return ResponseEntity.ok(incidentModerationService.getIncidentByIncidentId(incidentId));
    }

    @GetMapping("/get/deleted")
    public ResponseEntity<Page<IncidentDetailsDTO>> getDeletedIncidents(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.getDeletedIncidents(pageable));
    }

    @GetMapping("/get/category")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterByCategory(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize, @RequestParam String category) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.filterByCategory(category, pageable));
    }

    @GetMapping("/get/severity")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterBySeverity(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize, @RequestParam String severity) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.filterBySeverity(severity, pageable));
    }

    @GetMapping("/get/status")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterByStatus(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize, @RequestParam String status) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.filterByStatus(status, pageable));
    }

    @GetMapping("/get/reportedBy/{userId}")
    public ResponseEntity<Page<IncidentDetailsDTO>> getReportsByUser(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize, @PathVariable Long userId) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.getReportsByUser(userId, pageable));
    }

    @GetMapping("/get/reportedBy/{userId}/{incidentId}")
    public ResponseEntity<IncidentDetailsDTO> getIncidentReportedBy(@PathVariable Long userId, @PathVariable Long incidentId) {
        return ResponseEntity.ok(incidentModerationService.getIncidentReportedBy(userId, incidentId));
    }

    @GetMapping("/comment/get/commentBy/{userId}")
    public ResponseEntity<Page<CommentDetailsDTO>> getCommentsByUser(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize, @PathVariable Long userId) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("createdAt").descending());
        return ResponseEntity.ok(incidentModerationService.getCommentsByUser(userId, pageable));
    }

    @GetMapping("/get/commentedBy/{userId}/{commentId}")
    public ResponseEntity<CommentDetailsDTO> getCommentByUserId(@PathVariable Long commentId, @PathVariable Long userId) {
        return ResponseEntity.ok(incidentModerationService.getCommentIncidentId(commentId, userId));
    }

    @GetMapping("/{incidentId}/get/comments")
    public ResponseEntity<Page<CommentDetailsDTO>> getCommentsUnderIncident(@PathVariable("incidentId") Long incidentId) {
        return ResponseEntity.ok(incidentModerationService.getCommentsUnderIncident(incidentId));
    }

    @GetMapping("/comment/get/{commentId}")
    public ResponseEntity<CommentDetailsDTO> getCommentByCommentId(@PathVariable Long commentId) {
        return ResponseEntity.ok(incidentModerationService.getCommentByCommentId(commentId));
    }

    @PostMapping("/{reportId}/verify")
    public ResponseEntity<IncidentDTO> verifyIncident(Authentication authentication, @PathVariable Long reportId) {
        String adminEmail = authFacade.extractEmail(authentication);

        authentication.getAuthorities().forEach(a ->
                logger.info("AUTHORITY IN CONTEXT = {}", a.getAuthority())
        );

        return ResponseEntity.ok(incidentModerationService.verifyIncident(adminEmail, reportId));
    }

    @PostMapping("/{reportId}/publish")
    public ResponseEntity<IncidentDTO> publishIncident(@PathVariable Long reportId, Authentication authentication) {
        String adminEmail = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.publishIncident(reportId, adminEmail));
    }

    @PostMapping("/{reportId}/reject")
    private ResponseEntity<IncidentDTO> rejectIncident(@PathVariable Long reportId, Authentication authentication, @RequestParam String reason) {
        String email = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.rejectIncident(reportId, email, reason));
    }

    @PostMapping("/{reportId}/flag")
    public ResponseEntity<IncidentDTO> flagIncident(@PathVariable Long reportId, Authentication authentication, @RequestParam String reason) {
        String email = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.flagIncident(reportId, email, reason));
    }

    @PostMapping("/delete/{reportId}")
    public ResponseEntity<String> deleteReportById(Authentication authentication, @PathVariable Long reportId) {
        String email = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.deleteReportById(email, reportId));
    }

}
