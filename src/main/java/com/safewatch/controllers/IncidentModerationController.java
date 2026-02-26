package com.safewatch.controllers;

import com.safewatch.DTOs.CommentDTO;
import com.safewatch.DTOs.IncidentDTO;
import com.safewatch.security.UserPrincipal;
import com.safewatch.services.IncidentModerationService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/incident")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class IncidentModerationController {
    private final IncidentModerationService incidentModerationService;
    private final Logger logger = LoggerFactory.getLogger(IncidentModerationController.class);
    //re-assigning roles -> user-moderator when certain requirements are met -> send an alert to admin email

    private String extractEmail(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Unauthenticated");
        }
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        assert userPrincipal != null;
        return userPrincipal.getUsername();
    }

    @GetMapping("/get-all")
    public ResponseEntity<Page<IncidentDTO>> getAllIncidents(@RequestParam(defaultValue = "0") int pageNumber, @RequestParam(defaultValue = "10") int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("reportedAt").descending());
        return ResponseEntity.ok(incidentModerationService.getAllReports(pageable));
    }

    @GetMapping("/get/{incidentId}")
    public ResponseEntity<IncidentDTO> getIncidentByIncidentId(@PathVariable("incidentId") Long incidentId) {
        return ResponseEntity.ok(incidentModerationService.getIncidentByIncidentId(incidentId));
    }

    @GetMapping("/get/deleted")
    public ResponseEntity<Page<IncidentDTO>> getDeletedIncidents(@RequestParam(defaultValue = "0")int pageNumber,@RequestParam(defaultValue = "10") int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber,pageSize, Sort.by("reportedAt").ascending());
        return ResponseEntity.ok(incidentModerationService.getDeletedIncidents(pageable));
    }

    @PostMapping("/{reportId}/verify")
    public ResponseEntity<IncidentDTO> verifyIncident(Authentication authentication, @PathVariable Long reportId) {
        String adminEmail = extractEmail(authentication);

        authentication.getAuthorities().forEach(a ->
                logger.info("AUTHORITY IN CONTEXT = {}", a.getAuthority())
        );

        return ResponseEntity.ok(incidentModerationService.verifyIncident(adminEmail, reportId));
    }

    @GetMapping("/comment/get/{incidentId}")
    public ResponseEntity<Page<CommentDTO>> getCommentByIncidentId(@PathVariable Long incidentId, @RequestParam(defaultValue = "0")int pageNumber,@RequestParam(defaultValue = "10") int pageSize) {
        Pageable pageable = PageRequest.of(pageNumber,pageSize,Sort.by("createdAt").ascending());
        return ResponseEntity.ok(incidentModerationService.getCommentByIncidentID(incidentId,pageable));
    }

    @GetMapping("/comment/get/{incidentId}/{commentId}")
    public ResponseEntity<CommentDTO> getCommentByIdAndIncidentId(@PathVariable Long incidentId,@PathVariable Long commentId){
        return ResponseEntity.ok(incidentModerationService.getCommentByIdAndIncidentId(incidentId,commentId));
    }

    @PostMapping("/{reportId}/publish")
    public ResponseEntity<IncidentDTO> publishIncident(@PathVariable Long reportId, Authentication authentication) {
        String adminEmail = extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.publishIncident(reportId, adminEmail));
    }

    @PostMapping("/{reportId}/reject")
    private ResponseEntity<IncidentDTO> rejectIncident(@PathVariable Long reportId, Authentication authentication, @RequestParam String reason) {
        String email = extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.rejectIncident(reportId, email, reason));
    }

    @PostMapping("/{reportId}/flag")
    public ResponseEntity<IncidentDTO> flagIncident(@PathVariable Long reportId, Authentication authentication, @RequestParam String reason) {
        String email = extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.flagIncident(reportId, email, reason));
    }

    @PostMapping("/report/archive/{reportId}")
    public ResponseEntity<String> deleteReportById(Authentication authentication, @PathVariable Long reportId) {
        String email = extractEmail(authentication);
        return ResponseEntity.ok(incidentModerationService.deleteReportById(email, reportId));
    }

}
