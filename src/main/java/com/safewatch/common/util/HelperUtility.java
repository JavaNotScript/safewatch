package com.safewatch.common.util;

import com.safewatch.auth.internal.domain.User;
import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.comment.internal.domain.Comment;
import com.safewatch.comment.internal.dto.CommentDTO;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.common.exceptions.InvalidIncidentException;
import com.safewatch.common.domain.Media;
import com.safewatch.common.dto.MediaDTO;
import com.safewatch.incident.internal.domain.Incident;
import com.safewatch.incident.internal.domain.Severity;
import com.safewatch.incident.internal.dto.IncidentDTO;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import com.safewatch.incident.internal.util.ReportRequest;

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

    public static CurrentUserDTO convertToDTO(User user) {
        return new CurrentUserDTO(
                user.getUserId(),
                user.getEmail(),
                user.getFName(),
                user.getSName(),
                user.getCreatedAt(),
                user.getUserRole().getRoleName()
        );
    }

    public static IncidentDTO convertToDTO(Incident incident) {
        return new IncidentDTO(
                incident.getIncidentId(),
                incident.getReportedBy(),
                incident.getTitle(),
                incident.getDescription(),
                incident.getLocation(),
                incident.getSeverity(),
                incident.getIncidentCategory(),
                incident.getStatus(),
                incident.getVersion(),
                incident.getReportedAt(),
                incident.getDeletedAt()
        );
    }

    public static IncidentDetailsDTO convertToDTO(Incident incident, List<Media> media) {
        return new IncidentDetailsDTO(
                incident.getIncidentId(),
                incident.getReportedBy(),
                incident.getTitle(),
                incident.getDescription(),
                incident.getLocation(),
                incident.getSeverity(),
                incident.getIncidentCategory(),
                incident.getStatus(),
                incident.getVersion(),
                incident.getReportedAt(),
                incident.getDeletedAt(),
                convertToMediaDTO(media)
        );
    }

    public static IncidentDetailsDTO convertToDTO(IncidentDTO incident, List<Media> mediaList) {
        return new IncidentDetailsDTO(
                incident.incidentId(),
                incident.reportedBy(),
                incident.title(),
                incident.description(),
                incident.location(),
                incident.severity(),
                incident.incidentCategory(),
                incident.status(),
                incident.version(),
                incident.reportedAt(),
                incident.deletedAt(),
                convertToMediaDTO(mediaList)
        );
    }

    public static CommentDTO convertToDTO(Comment comment) {
        return new CommentDTO(
                comment.getCommentId(),
                comment.getComment(),
                comment.getUserId(),
                comment.getIncidentId(),
                comment.getCreatedAt()
        );
    }

    public static CommentDetailsDTO convertCommentDTO(Comment comment, List<Media> media) {
        return new CommentDetailsDTO(
                comment.getCommentId(),
                comment.getComment(),
                comment.getUserId(),
                comment.getIncidentId(),
                comment.getCreatedAt(),
                convertToMediaDTO(media)
        );
    }

    public static CommentDetailsDTO convertToDTO(CommentDTO comment, List<Media> mediaList) {
        return new CommentDetailsDTO(
                comment.commentId(),
                comment.comment(),
                comment.userId(),
                comment.incidentId(),
                comment.createAt(),
                convertToMediaDTO(mediaList)
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

    public static List<MediaDTO> convertToMediaDTO(List<Media> mediaList) {
        return mediaList.stream().map(HelperUtility::convertToDTO).collect(Collectors.toList());
    }

}
