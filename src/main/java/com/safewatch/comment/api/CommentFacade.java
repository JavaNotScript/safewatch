package com.safewatch.comment.api;

import com.safewatch.comment.internal.dto.CommentDTO;
import com.safewatch.comment.internal.dto.CommentDetailsDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CommentFacade {

    CommentDTO findByCommentId(Long commentId);

    Page<CommentDetailsDTO> getCommentsByIncident(Long incidentId, Pageable pageable);

    Page<CommentDetailsDTO> findByUserUserId(Long userId,Pageable pageable);
}
