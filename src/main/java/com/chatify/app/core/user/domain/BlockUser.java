package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name="block_user")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BlockUser {

    @EmbeddedId
    private BlockUserId id;

    @ManyToOne(fetch=FetchType.LAZY)
    @MapsId("blockerId")
    @JoinColumn(name="blocker_id")
    private User blocker;

    @ManyToOne(fetch=FetchType.LAZY)
    @MapsId("blockedId")
    @JoinColumn(name="blocked_id")
    private User blocked;

    @Column(name="reason", length=255)
    private String reason;

    @Column(name="created_at", nullable=false, updatable=false)
    private LocalDateTime createdAt;

    @Builder
    public BlockUser(User blocker, User blocked, String reason){
        this.id = new BlockUserId(blocker.getId(), blocked.getId());
        this.blocker = blocker;
        this.blocked = blocked;
        this.reason = reason;
    }

    @PrePersist
    protected void onCreate(){
        this.createdAt = LocalDateTime.now();
    }
}
