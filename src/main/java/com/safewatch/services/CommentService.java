package com.safewatch.services;

import com.safewatch.DTOs.CommentDetailsDTO;
import com.safewatch.DTOs.MediaDTO;
import com.safewatch.exceptions.IncidentNotFoundException;
import com.safewatch.exceptions.InvalidIncidentException;
import com.safewatch.models.*;
import com.safewatch.repositories.CommentRepository;
import com.safewatch.repositories.CurrentUserRepository;
import com.safewatch.repositories.IncidentRepository;
import com.safewatch.repositories.MediaRepository;
import com.safewatch.util.HelperUtility;
import com.safewatch.util.reportRelated.CommentRequest;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    private final CurrentUserRepository userRepository;
    private final IncidentRepository incidentRepository;
    private final MediaRepository mediaRepository;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());


    @Transactional
    public CommentDetailsDTO makeComment(Long userId, CommentRequest request, List<MultipartFile> media, Long incidentId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("Email not found"));

        if (user.isLocked()) throw new LockedException("account is locked");

        if (!user.isEnabled()) throw new DisabledException("account is not enabled");

        if (user.isCredentialsExpired()) throw new CredentialsExpiredException("account credentials expired");

        Incident incident = incidentRepository.findById(incidentId).orElseThrow(() -> new IncidentNotFoundException("Incident of id " + incidentId + ", not found"));

        if (incident.getStatus() != Status.PUBLISHED) {
            throw new InvalidIncidentException("Cannot comment on unpublished incidents.");
        }

        if (incident.getDeletedAt() != null) {
            throw new InvalidIncidentException("Cannot comment on deleted incidents.");
        }

        Comment comment = new Comment();
        comment.setIncident(incident);
        comment.setUser(user);
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
                medFile.setComment(comment);
                medFile.setSizeBytes(file.getSize());
                medFile.setContentType(contentType);
                medFile.setOriginalFilename(fileName);
                medFile.setStorageKey(storageKey);
                medFile.setOwner(user);

                mediaRepository.save(medFile);
            }
        }

        List<Media> mediaList = mediaRepository.findByCommentCommentIdAndDeletedAtIsNull(savedComment.getCommentId());
        return HelperUtility.convertToDTO(comment, mediaList);
    }

    public Page<CommentDetailsDTO> getAllComments(Long incidentId) {
        Pageable pageable = PageRequest.of(0, 10, Sort.by("createdAt").descending());

        Page<Comment> commentPage = commentRepo.findVisibleByIncident(incidentId, pageable);
        List<Comment> commentList = commentPage.getContent();

        if (commentList.isEmpty()) return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());

        List<Long> commentIds = commentList.stream().map(Comment::getCommentId).toList();

        List<Media> mediaList = mediaRepository.findByCommentCommentIdAndDeletedAtIsNull(commentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream().collect(Collectors.groupingBy(m -> m.getIncident().getIncidentId()));

        List<CommentDetailsDTO> commentDetailsDTOList = commentList.stream()
                .map(c -> HelperUtility.convertToDTO(c, mediaMap.getOrDefault(c.getCommentId(), List.of())))
                .toList();

        return new PageImpl<>(commentDetailsDTOList, pageable, commentPage.getTotalElements());
    }

    public CommentDetailsDTO getCommentUnderIncidentById(long commentId, Long incidentId) {
        Comment comment = commentRepo.findVisibleCommentByCommentId(commentId, incidentId);
        List<Media> media = mediaRepository.findByCommentCommentIdAndDeletedAtIsNull(incidentId);

        return HelperUtility.convertToDTO(comment, media);
    }

    public CommentDetailsDTO updateCommentUnderIncident(Long userId, @Valid CommentRequest request, Long commentId) {
        Comment comment = commentRepo.findById(commentId).orElseThrow(() -> new RuntimeException("Comment with id " + commentId + " not found"));
        User user = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException("user not found"));

        if (!comment.getUser().getUserId().equals(user.getUserId())) {
            throw new AccessDeniedException("User does not have permission to update comment");
        }

        comment.setComment(request.description());

        Comment savedComment = commentRepo.save(comment);
        List<Media> mediaList = mediaRepository.findByCommentCommentIdAndDeletedAtIsNull(savedComment.getCommentId());

        return HelperUtility.convertToDTO(savedComment, mediaList);
    }

    public List<MediaDTO> addMediaToComment( Long incidentId,Long commentId, List<MultipartFile> media) {
        Comment comment = commentRepo.findVisibleCommentByCommentId(commentId, incidentId);

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
                medFile.setComment(comment);
                medFile.setSizeBytes(file.getSize());
                medFile.setContentType(contentType);
                medFile.setOriginalFilename(fileName);
                medFile.setStorageKey(storageKey);
                medFile.setOwner(comment.getUser());

                mediaRepository.save(medFile);
            }
        }

        List<Media> mediaList = mediaRepository.findByCommentCommentIdAndDeletedAtIsNull(comment.getCommentId());
        return HelperUtility.convertToMediaDTO(mediaList);
    }

    @Transactional
    public void deleteMyComment(Long userId, long commentId, String reason) {
        Comment comment = commentRepo.findById(commentId).orElseThrow(() -> new RuntimeException("Comment with id " + commentId + " not found"));

        if (!comment.getUser().getUserId().equals(userId)) {
            throw new AccessDeniedException("User does not have permission to delete comment");
        }

        comment.setDeletedAt(OffsetDateTime.now());
        comment.setDeletedBy(userId);
        comment.setDeletedReason(reason);
        comment.setDeleted(true);

        commentRepo.save(comment);
    }
}
