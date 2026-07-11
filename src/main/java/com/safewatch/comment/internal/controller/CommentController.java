package com.safewatch.comment.internal.controller;

import com.safewatch.common.dto.MediaDTO;
import com.safewatch.auth.api.AuthFacade;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.comment.internal.service.CommentService;
import com.safewatch.comment.internal.util.CommentRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/comment")
public class CommentController {
    private final CommentService service;
    private final AuthFacade authFacade;

    @GetMapping("/get-all/{incidentId}")
    public ResponseEntity<Page<CommentDetailsDTO>> getAllComments(@PathVariable Long incidentId) {
        return ResponseEntity.ok(service.getAllComments(incidentId));
    }

    @GetMapping("/get/{commentId}/{incidentId}")
    public ResponseEntity<CommentDetailsDTO> getCommentUnderIncidentById(@PathVariable("commentId") Long commentId, @PathVariable Long incidentId) {
        return ResponseEntity.ok(service.getCommentUnderIncidentById(commentId, incidentId));
    }

    @PostMapping(value = "/{incidentId},", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CommentDetailsDTO> makeComment(Authentication authentication, @Valid @RequestBody CommentRequest request, @RequestPart(required = false) List<MultipartFile> media, @PathVariable Long incidentId) {
        Long userId = authFacade.extractUserId(authentication);
        return ResponseEntity.ok(service.makeComment(userId, request, media, incidentId));
    }

    @PostMapping(value = "{incidentId}/{commentId}/media", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<MediaDTO>> addMediaToComment(@PathVariable Long incidentId, @PathVariable Long commentId, @RequestPart(required = false, value = "images") List<MultipartFile> media) {
        return ResponseEntity.ok(service.addMediaToComment(incidentId, commentId, media));
    }

    @PutMapping("/update/{incidentId}/{commentId}")
    public ResponseEntity<CommentDetailsDTO> updateCommentUnderIncident(Authentication authentication, @Valid @RequestBody CommentRequest request, @PathVariable long commentId) {
        Long userId = authFacade.extractUserId(authentication);

        return ResponseEntity.ok(service.updateCommentUnderIncident(userId, request, commentId));
    }

    @DeleteMapping("/delete/{commentId}")
    public ResponseEntity<Void> deleteMyComment(Authentication authentication, @PathVariable long commentId, @RequestParam(required = false) String reason) {
        Long userId = authFacade.extractUserId(authentication);
        service.deleteMyComment(userId, commentId, reason);
        return ResponseEntity.ok().build();
    }
}
