package com.safewatch.repositories;

import com.safewatch.models.Media;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface MediaRepository extends JpaRepository<Media, UUID> {
    @Query("SELECT m FROM Media m WHERE m.incident.incidentId IN (:incidentId) AND m.deletedAt IS NULL")
    List<Media> findByIncidentIncidentIdAndDeletedAtIsNull(@Param("incidentId") List<Long> incidentId);

    List<Media> getByIncidentIncidentIdAndDeletedAtIsNull(@Param("incidentId") Long incidentId);

    @Query("SELECT c FROM Media c WHERE c.comment.commentId IN (:commentIds) AND c.deletedAt IS NULL")
    List<Media> findByCommentCommentIdAndDeletedAtIsNull(@Param("commentIds") List<Long> commentIds);

    List<Media> findByCommentCommentIdAndDeletedAtIsNull(Long commentId);

    @Query("SELECT m FROM Media m WHERE m.incident.incidentId IN (:incidentIds)")
    List<Media> findByIncidentIncidentId(@Param("incidentIds") List<Long> incidentIds);

    List<Media> findByIncidentIncidentId(Long incidentId);

    @Query("SELECT m FROM Media m WHERE m.comment.commentId = :commentId")
    List<Media> findByCommentCommentId(@Param("commentId") Long commentId);

    @Query("SELECT m FROM Media m WHERE m.comment.commentId IN (:commentIds)")
    List<Media> findByCommentCommentId(@Param("commentIds") List<Long> commentIds);
}
