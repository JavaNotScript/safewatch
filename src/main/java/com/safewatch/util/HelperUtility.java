package com.safewatch.util;

import com.safewatch.DTOs.*;
import com.safewatch.exceptions.InvalidIncidentException;
import com.safewatch.models.*;
import com.safewatch.util.reportRelated.ReportRequest;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class HelperUtility {
    private final static SecureRandom random = new SecureRandom();


    public static String generateRefreshToken() {
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static CurrentUserDTO convertToDTO(User user) {
        return new CurrentUserDTO(
                user.getEmail(),
                user.getFName(),
                user.getSName(),
                user.getCreatedAt()
        );
    }

    public static IncidentDTO convertToDTO(Incident incident) {
        return new IncidentDTO(
                incident.getIncidentId(),
                incident.getTitle(),
                incident.getLocation(),
                incident.getSeverity(),
                incident.getIncidentCategory(),
                incident.getStatus(),
                incident.getVersion(),
                incident.getReportedAt()
        );
    }

    public static IncidentDetailsDTO convertToDTO(Incident incident, List<Media> media) {
        return new IncidentDetailsDTO(
                incident.getIncidentId(),
                incident.getTitle(),
                incident.getDescription(),
                incident.getLocation(),
                incident.getSeverity(),
                incident.getIncidentCategory(),
                incident.getStatus(),
                incident.getVersion(),
                incident.getReportedAt(),
                convertToDetailsDTO(media)

        );
    }

    public static MediaDTO convertToDTO(Media media) {
        return new MediaDTO(
                media.getMediaId(),
                media.getOriginalFilename(),
                media.getContentType(),
                media.getSizeBytes(),
                media.getCreatedAt()
        );
    }

    public static List<MediaDTO> convertToDetailsDTO(List<Media> mediaList) {
        return mediaList.stream().map(HelperUtility::convertToDTO).collect(Collectors.toList());
    }

    public static CommentDTO convertToDTO(Comment comment) {
        return new CommentDTO(
                comment.getIncident().getIncidentId(),
                comment.getUser().getUserId(),
                comment.getComment(),
                comment.getCreatedAt()
        );
    }

    public static CommentDetailsDTO convertToDTO(Comment comment, List<Media> media) {
        return new CommentDetailsDTO(
                comment.getCommentId(),
                comment.getComment(),
                comment.getUser().getUserId(),
                comment.getIncident().getIncidentId(),
                comment.getCreatedAt(),
                convertToDetailsDTO(media)

        );
    }

    public static void validateReport(ReportRequest req, Severity severity) {

        if (req.getTitle() == null || req.getTitle().length() < 5) {
            throw new InvalidIncidentException("Title too short/null");
        }
        if (req.getDescription() == null || req.getDescription().length() < 20)
            throw new InvalidIncidentException("Description too short");

        if (severity == Severity.EXTREME && req.getDescription().length() < 80)
            throw new InvalidIncidentException("Extreme incidents require detailed description");

        if (req.getLocation() == null || req.getLocation().isBlank())
            throw new InvalidIncidentException("Location is required");
    }


}
