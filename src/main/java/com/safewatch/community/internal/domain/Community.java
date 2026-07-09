package com.safewatch.community.internal.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;

@Entity
@Table(name = "community")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Community {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long communityId;

    @Column(name = "admin_id")
    private Long adminId;

    @Column(name = "community_name")
    private String communityName;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "community_visibility")
    private CommunityVisibility communityVisibility;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "community_audience")
    private CommunityAudience communityAudience;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "community_status")
    private CommunityStatus communityStatus;

    @CreationTimestamp
    @Column(name = "created_at")
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private OffsetDateTime updatedAt;
}
