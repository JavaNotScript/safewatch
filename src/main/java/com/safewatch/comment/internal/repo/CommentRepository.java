package com.safewatch.comment.internal.repo;

import com.safewatch.comment.internal.domain.Comment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CommentRepository extends JpaRepository<Comment, Long> {

    @Query("""
               select c from Comment c
               where c.incidentId = :incidentId
                 and c.isDeleted = false
                 order by c.createdAt desc
            """)
    Page<Comment> findVisibleByIncident(@Param("incidentId") Long incidentId, Pageable pageable);

    @Query("""
              select c from Comment c
              where c.incidentId = :incidentId
              order by c.createdAt desc
            """)
    Page<Comment> findAllByIncident(@Param("incidentId") Long incidentId, Pageable pageable);

    @Query(
            "SELECT c FROM Comment c WHERE c.incidentId = :incidentId AND c.commentId = :commentId AND c.isDeleted = false AND c.deletedAt IS NULL"
    )
    Comment findVisibleByCommentId(Long commentId, Long incidentId);

    Page<Comment> findByUserId(Long userId, Pageable pageable);
}
