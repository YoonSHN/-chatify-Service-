package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Table(name="friendship",
    uniqueConstraints= {
        @UniqueConstraint(
                name = "friendship_uk",
                columnNames = {"requester_id" , "receiver_id"}
        )
    })
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Getter
@SQLDelete(sql = "UPDATE friendship SET deleted_at = NOW() WHERE friendship_id = ?")
@Where(clause = "deleted_at IS NULL")
public class Friendship {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="friendship_id")
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="requester_id", nullable=false)
    private User requester;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="receiver_id", nullable=false)
    private User receiver;

    @Column(name="status", nullable=false)
    @Enumerated
    private FriendshipStatus status;

    @Column(name="created_at", nullable=false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    public static Friendship create(User requester, User receiver){
        Friendship friendship = new Friendship();
        friendship.requester = requester;
        friendship.receiver = receiver;
        friendship.status = FriendshipStatus.PENDING;
        return friendship;
    }

    public void accept(){
        this.status = FriendshipStatus.ACCEPTED;
    }
    public void decline(){
        this.status = FriendshipStatus.DECLINED;
    }

}
