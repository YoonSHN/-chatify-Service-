package com.chatify.app.core.system.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Table(name="announcement")
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@SQLDelete(sql = "UPDATE announcement SET deleted_at = NOW() WHERE announcement_id = ?" )
@Where(clause = "deleted_at Is NULL")
@Getter
public class Announcement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="announcement_id")
    private Long id;

    @Column(name="author", length = 50, nullable=false)
    private String author = "관리자";

    @Column(name="title", length = 255, nullable = false)
    private String title;

    @Lob
    @Column(name="content")
    private String content;

    @CreationTimestamp
    @Column(name="created_at", nullable=false, updatable=false)
    private LocalDateTime createdAt;

    @Column(name="published_at")
    private LocalDateTime publishedAt;

    @Column(name="updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    @Builder
    public Announcement(String author, String title){
        this.author = author;
        this.title = title;
    }

    public void publish(){
        this.publishedAt = LocalDateTime.now();
    }
}
