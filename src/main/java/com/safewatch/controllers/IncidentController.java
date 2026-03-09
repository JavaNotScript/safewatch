package com.safewatch.controllers;

import com.safewatch.DTOs.IncidentDetailsDTO;
import com.safewatch.DTOs.MediaDTO;
import com.safewatch.security.UserPrincipal;
import com.safewatch.services.IncidentService;
import com.safewatch.util.reportRelated.ReportRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/incident")
@RequiredArgsConstructor
public class IncidentController {
    private final IncidentService service;

    private long extractId(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Unauthenticated");
        }

        Object principal = authentication.getPrincipal();

        if (!(principal instanceof UserPrincipal up)) {
            throw new AccessDeniedException("Unauthenticated");
        }

        return up.getUserId();
    }

    @GetMapping("/get/reports")
    public ResponseEntity<Page<IncidentDetailsDTO>> getAllReports() {
        return ResponseEntity.ok(service.getAllReports());
    }

    @GetMapping("/get/{incidentId}")
    public ResponseEntity<IncidentDetailsDTO> getReportById(@PathVariable Long incidentId) {
        return ResponseEntity.ok(service.getReportById(incidentId));
    }

    @GetMapping("/me/get/all")
    public ResponseEntity<Page<IncidentDetailsDTO>> getMyReports(Authentication authentication) {
        Long userId = extractId(authentication);
        return ResponseEntity.ok(service.getMyReports(userId));
    }

    @GetMapping("/me/get/status")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterByStatus(Authentication authentication, @RequestParam String status, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int size) {
        Long userId = extractId(authentication);
        return ResponseEntity.ok(service.filterByStatus(userId, status, page, size));
    }

    @GetMapping("/get/category")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterByCategory(@RequestParam String category, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(service.filterByCategory(category, page, size));
    }

    @GetMapping("/get/severity")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterBySeverity(@RequestParam String severity, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(service.filterBySeverity(severity, page, size));
    }

    @PostMapping(value = "/report", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<IncidentDetailsDTO> reportIncident(Authentication authentication, @RequestBody ReportRequest request, @RequestPart(value = "images", required = false) List<MultipartFile> images) {
        Long userId = extractId(authentication);
        return ResponseEntity.ok(service.reportIncident(userId, request, images));
    }

    @PostMapping(value = "/{incidentId}/media", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<MediaDTO>> addMediaToReport(@PathVariable Long incidentId, @RequestPart(required = false, value = "images") List<MultipartFile> media) {
        return ResponseEntity.ok(service.addMediaToReport(incidentId, media));
    }

    @PutMapping("/update/{reportId}")
    public ResponseEntity<IncidentDetailsDTO> updateReport(Authentication authentication, @PathVariable Long reportId, @RequestBody ReportRequest request) {
        Long userId = extractId(authentication);
        return ResponseEntity.ok(service.updateReport(userId, reportId, request));
    }

    @DeleteMapping("/delete/{reportId}")
    public ResponseEntity<Void> deleteReportById(Authentication authentication, @PathVariable Long reportId, @RequestBody(required = false) String reason) {
        Long userId = extractId(authentication);
        service.deleteIncident(userId, reportId, reason);
        return ResponseEntity.ok().build();
    }
}
