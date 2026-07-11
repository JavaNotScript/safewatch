package com.safewatch.common.moderation;

import com.safewatch.common.domain.Media;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface MediaRepository extends JpaRepository<Media, UUID> {
    @Query("SELECT m FROM Media m WHERE m.incidentId IN (:incidentId) AND m.deletedAt IS NULL")
    List<Media> findByIncidentIdAndDeletedAtIsNull(@Param("incidentId") List<Long> incidentId);

    List<Media> getByIncidentIdAndDeletedAtIsNull(@Param("incidentId") Long incidentId);

    @Query("SELECT c FROM Media c WHERE c.commentId IN (:commentIds) AND c.deletedAt IS NULL")
    List<Media> findByCommentIdAndDeletedAtIsNull(@Param("commentIds") List<Long> commentIds);

    List<Media> findByCommentIdAndDeletedAtIsNull(Long commentId);

    @Query("SELECT m FROM Media m WHERE m.incidentId IN (:incidentIds)")
    List<Media> findByIncidentIncidentId(@Param("incidentIds") List<Long> incidentIds);


    @Query("SELECT m FROM Media m WHERE m.commentId = :commentId")
    List<Media> findByCommentId(@Param("commentId") Long commentId);

    @Query("SELECT m FROM Media m WHERE m.commentId IN (:commentIds)")
    List<Media> findByCommentId(@Param("commentIds") List<Long> commentIds);

    List<Media> findByIncidentId(Long getIncidentId);
}
