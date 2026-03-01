package com.safewatch.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "media")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Media {

    @Id
    @GeneratedValue
    @Column(name = "media_id")
    private UUID mediaId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner",nullable = false)
    private User owner;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn (name = "incident_id")
    private Incident incident;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "comment_id")
    private Comment comment;

    @Column(name = "storage_key", nullable = false,length = 500)
    private String storageKey;

    @Column(name = "original_filename",nullable = false,length = 250)
    private String originalFilename;

    @Column(name = "content_type",nullable = false,length = 100)
    private String contentType;

    @Column(name = "size_bytes",nullable = false)
    private long sizeBytes;

    @CreationTimestamp
    @Column(name = "created_at")
    private OffsetDateTime createdAt;

    @Column(name = "deleted_at")
    private OffsetDateTime deletedAt;

    @Column(name = "deleted_by")
    private Long deletedBy;
}
