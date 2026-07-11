package com.safewatch.incident.internal.controller;

import com.safewatch.common.dto.MediaDTO;
import com.safewatch.auth.api.AuthFacade;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import com.safewatch.incident.internal.service.IncidentService;
import com.safewatch.incident.internal.util.ReportRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/incident")
@RequiredArgsConstructor
public class IncidentController {
    private final IncidentService service;
    private final AuthFacade authFacade;

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
        Long userId = authFacade.extractUserId(authentication);
        return ResponseEntity.ok(service.getMyReports(userId));
    }

    @GetMapping("/me/get/status")
    public ResponseEntity<Page<IncidentDetailsDTO>> filterByStatus(Authentication authentication, @RequestParam String status, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int size) {
        Long userId = authFacade.extractUserId(authentication);
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
        Long userId = authFacade.extractUserId(authentication);
        return ResponseEntity.ok(service.reportIncident(userId, request, images));
    }

    @PostMapping(value = "/{incidentId}/media", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<MediaDTO>> addMediaToReport(@PathVariable Long incidentId, @RequestPart(required = false, value = "images") List<MultipartFile> media) {
        return ResponseEntity.ok(service.addMediaToReport(incidentId, media));
    }

    @PutMapping("/update/{reportId}")
    public ResponseEntity<IncidentDetailsDTO> updateReport(Authentication authentication, @PathVariable Long reportId, @RequestBody ReportRequest request) {
        Long userId = authFacade.extractUserId(authentication);
        return ResponseEntity.ok(service.updateReport(userId, reportId, request));
    }

    @DeleteMapping("/delete/{reportId}")
    public ResponseEntity<Void> deleteReportById(Authentication authentication, @PathVariable Long reportId, @RequestBody(required = false) String reason) {
        Long userId = authFacade.extractUserId(authentication);
        service.deleteIncident(userId, reportId, reason);
        return ResponseEntity.ok().build();
    }
}
