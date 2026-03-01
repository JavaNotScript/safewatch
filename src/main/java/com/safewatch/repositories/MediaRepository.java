package com.safewatch.repositories;

import com.safewatch.models.Comment;
import com.safewatch.models.Incident;
import com.safewatch.models.Media;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MediaRepository extends JpaRepository<Media,Long> {
    List<Media> findByIncidentIncidentIdAndDeletedAtIsNull(Long incidentId);

    List<Media> findByIncidentAndDeletedAtIsNull(Incident incident);

    List<Media> findByCommentAndDeletedAtIsNull(Comment comment);
}
