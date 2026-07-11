package com.safewatch.comment.api;

import com.safewatch.comment.internal.domain.Comment;
import com.safewatch.comment.internal.dto.CommentDTO;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import com.safewatch.comment.internal.repo.CommentRepository;
import com.safewatch.common.exceptions.CommentException;
import com.safewatch.common.util.HelperUtility;
import com.safewatch.common.domain.Media;
import com.safewatch.common.moderation.MediaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CommentAdapter implements CommentFacade{
    private final CommentRepository commentRepository;
    private final MediaRepository mediaRepo;

    @Override
    public CommentDTO findByCommentId(Long commentId) {
        Comment comment = commentRepository.findById(commentId).orElseThrow(() -> new CommentException("comment not found"));

        return HelperUtility.convertToDTO(comment);
    }

    @Override
    public Page<CommentDetailsDTO> getCommentsByIncident(Long incidentId, Pageable pageable) {
        Page<Comment> commentPage = commentRepository.findAllByIncident(incidentId, pageable);

        if (commentPage.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());
        }

        List<Long> commentIds = commentPage.getContent().stream()
                .map(Comment::getCommentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByCommentId(commentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(Media::getCommentId));

        List<CommentDetailsDTO> dtoList = commentPage.getContent().stream()
                .map(c -> HelperUtility.convertCommentDTO(c, mediaMap.getOrDefault(c.getCommentId(), List.of())))
                .toList();

        return new PageImpl<>(dtoList, pageable, commentPage.getTotalElements());
    }

    @Override
    public Page<CommentDetailsDTO> findByUserUserId(Long userId, Pageable pageable) {
        Page<Comment> commentPage = commentRepository.findByUserId(userId,pageable);

        if (commentPage.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, commentPage.getTotalElements());
        }

        List<Long> commentIds = commentPage.getContent().stream()
                .map(Comment::getCommentId)
                .toList();

        List<Media> mediaList = mediaRepo.findByCommentId(commentIds);

        Map<Long, List<Media>> mediaMap = mediaList.stream()
                .collect(Collectors.groupingBy(Media::getCommentId));

        List<CommentDetailsDTO> dtoList = commentPage.getContent().stream()
                .map(c -> HelperUtility.convertCommentDTO(c, mediaMap.getOrDefault(c.getCommentId(), List.of())))
                .toList();

        return new PageImpl<>(dtoList, pageable, commentPage.getTotalElements());
    }
}
