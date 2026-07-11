package com.safewatch.comment.internal.service;

import com.safewatch.common.dto.MediaDTO;
import com.safewatch.auth.api.AuthFacade;
import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.auth.internal.dto.UserDTO;
import com.safewatch.comment.internal.domain.Comment;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.comment.internal.repo.CommentRepository;
import com.safewatch.comment.internal.util.CommentRequest;
import com.safewatch.common.exceptions.InvalidIncidentException;
import com.safewatch.common.util.HelperUtility;
import com.safewatch.incident.api.IncidentFacade;
import com.safewatch.incident.internal.domain.Status;
import com.safewatch.incident.internal.dto.IncidentDetailsDTO;
import com.safewatch.common.domain.Media;
import com.safewatch.common.moderation.MediaRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CommentService {
    private final CommentRepository commentRepo;
    private final MediaRepository mediaRepository;
    private final AuthFacade authFacade;
    private final IncidentFacade incidentFacade;


    @Transactional
    public CommentDetailsDTO makeComment(Long userId, CommentRequest request, List<MultipartFile> media, Long incidentId) {
        UserDTO user = authFacade.findByUserId(userId);

        if (user.isLocked()) throw new LockedException("account is locked");

        if (!user.isEnabled()) throw new DisabledException("account is not enabled");

        if (user.isCredentialExpired()) throw new CredentialsExpiredException("account credentials expired");

        IncidentDetailsDTO incident = incidentFacade.findById(incidentId);

        if (incident.status() != Status.PUBLISHED) {
            throw new InvalidIncidentException("Cannot comment on unpublished incidents.");
        }

        if (incident.deletedAt() != null) {
            throw new InvalidIncidentException("Cannot comment on deleted incidents.");
        }

        Comment comment = new Comment();
        comment.setIncidentId(incidentId);
        comment.setUserId(userId);
        comment.setComment(request.description());

        Comment savedComment = commentRepo.save(comment);

        if (media != null && !media.isEmpty()) {
            if (media.size() > 5) throw new InvalidIncidentException("Max 5 images allowed.");

            for (MultipartFile file : media) {
                if (file.isEmpty()) continue;

                String contentType = file.getContentType();

                if (contentType == null || !(contentType.equals("image/jpeg") || contentType.equals("image/png") || contentType.equals("image/webp"))) {
                    throw new InvalidIncidentException("Invalid media type. Only JPG,PNG,WEBP allowed.");
                }

                if (file.getSize() > 3_000_000) {
                    throw new InvalidIncidentException("Max image size allowed is 3MB");
                }

                String extension = switch (contentType) {
                    case "image/jpeg" -> ".jpg";
                    case "image/png" -> ".png";
                    case "image/webp" -> ".webp";
                    default -> "";
                };

                String fileName = UUID.randomUUID() + extension;
                String storageKey = "comment/" + savedComment.getCommentId() + "/" + fileName;

                Path root = Paths.get("uploads");
                Path target = root.resolve(storageKey);

                try {
                    Files.createDirectories(target.getParent());
                    file.transferTo(target);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to store image", e);
                }

                Media medFile = new Media();
                medFile.setCommentId(comment.getCommentId());
                medFile.setSizeBytes(file.getSize());
                medFile.setContentType(contentType);
                medFile.setOriginalFilename(fileName);
                medFile.setStorageKey(storageKey);
                medFile.setOwnerId(userId);

                mediaRepository.save(medFile);
            }
        }

        List<Media> mediaList = mediaRepository.findByCommentIdAndDeletedAtIsNull(savedComment.getCommentId());
        return HelperUtility.convertCommentDTO(savedComment,mediaList);
    }

    public Page<CommentDetailsDTO> getAllComments(Long incidentId) {
        Pageable pageable = PageRequest.of(0, 10, Sort.by("createdAt").descending());

        Page<Comment> commentPage = commentRepo.findVisibleByIncident(incidentId, pageable);
        List<Comment> commentList = commentPage.getContent();

        if (commentList.isEmpty()) return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());

        List<Long> commentIds = commentList.stream().map(Comment::getCommentId).toList();

        List<Media> mediaList = mediaRepository.findByCommentIdAndDeletedAtIsNull(commentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(Media::getIncidentId));

        List<CommentDetailsDTO> commentDetailsDTOList = commentList.stream()
                .map(c -> HelperUtility.convertCommentDTO(c, mediaMap.getOrDefault(c.getCommentId(), List.of())))
                .toList();

        return new PageImpl<>(commentDetailsDTOList, pageable, commentPage.getTotalElements());
    }

    public CommentDetailsDTO getCommentUnderIncidentById(long commentId, Long incidentId) {
        Comment comment = commentRepo.findVisibleByCommentId(commentId, incidentId);
        List<Media> media = mediaRepository.findByCommentIdAndDeletedAtIsNull(incidentId);

        return HelperUtility.convertCommentDTO(comment, media);
    }

    public CommentDetailsDTO updateCommentUnderIncident(Long userId, @Valid CommentRequest request, Long commentId) {
        Comment comment = commentRepo.findById(commentId).orElseThrow(() -> new RuntimeException("Comment with id " + commentId + " not found"));
        CurrentUserDTO user = authFacade.findUserByUserId(userId);

        if (!comment.getUserId().equals(user.userId())) {
            throw new AccessDeniedException("User does not have permission to update comment");
        }

        comment.setComment(request.description());

        Comment savedComment = commentRepo.save(comment);
        List<Media> mediaList = mediaRepository.findByCommentIdAndDeletedAtIsNull(savedComment.getCommentId());

        return HelperUtility.convertCommentDTO(savedComment, mediaList);
    }

    public List<MediaDTO> addMediaToComment(Long incidentId, Long commentId, List<MultipartFile> media) {
        Comment comment = commentRepo.findVisibleByCommentId(commentId, incidentId);

        if (media != null && !media.isEmpty()) {
            if (media.size() > 5) throw new InvalidIncidentException("Max 5 images allowed.");

            for (MultipartFile file : media) {
                if (file.isEmpty()) continue;

                String contentType = file.getContentType();

                if (contentType == null || !(contentType.equals("image/jpeg") || contentType.equals("image/png") || contentType.equals("image/webp"))) {
                    throw new InvalidIncidentException("Invalid media type. Only JPG,PNG,WEBP allowed.");
                }

                if (file.getSize() > 3_000_000) {
                    throw new InvalidIncidentException("Max image size allowed is 3MB");
                }

                String extension = switch (contentType) {
                    case "image/jpeg" -> ".jpg";
                    case "image/png" -> ".png";
                    case "image/webp" -> ".webp";
                    default -> "";
                };

                String fileName = UUID.randomUUID() + extension;
                String storageKey = "comment/" + comment.getCommentId() + "/" + fileName;

                Path root = Paths.get("uploads");
                Path target = root.resolve(storageKey);

                try {
                    Files.createDirectories(target.getParent());
                    file.transferTo(target);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to store image", e);
                }

                Media medFile = new Media();
                medFile.setCommentId(comment.getCommentId());
                medFile.setSizeBytes(file.getSize());
                medFile.setContentType(contentType);
                medFile.setOriginalFilename(fileName);
                medFile.setStorageKey(storageKey);
                medFile.setOwnerId(comment.getUserId());

                mediaRepository.save(medFile);
            }
        }

        List<Media> mediaList = mediaRepository.findByCommentIdAndDeletedAtIsNull(comment.getCommentId());
        return HelperUtility.convertToMediaDTO(mediaList);
    }

    @Transactional
    public void deleteMyComment(Long userId, long commentId, String reason) {
        Comment comment = commentRepo.findById(commentId).orElseThrow(() -> new RuntimeException("Comment with id " + commentId + " not found"));

        if (!comment.getUserId().equals(userId)) {
            throw new AccessDeniedException("User does not have permission to delete comment");
        }

        comment.setDeletedAt(OffsetDateTime.now());
        comment.setDeletedBy(userId);
        comment.setDeletedReason(reason);
        comment.setDeleted(true);

        commentRepo.save(comment);
    }
}
