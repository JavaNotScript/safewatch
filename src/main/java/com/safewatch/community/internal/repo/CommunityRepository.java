package com.safewatch.community.internal.repo;

import com.safewatch.community.internal.domain.Community;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface CommunityRepository extends JpaRepository<Community, Long> {

    @Query("""
            SELECT COUNT(c) > 0 FROM Community c WHERE c.communityName= :communityName
            """)
    boolean existsByCommunityName(@Param("communityName") String communityName);

    Optional<Community> findByCommunityName(String communityName);
}
