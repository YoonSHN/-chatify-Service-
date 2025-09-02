package com.chatify.app.core.chat.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Table(name="chat_room")
@SQLDelete(sql = "UPDATE chat_room SET deleted_at = NOW() WHERE room_id = ?")
@Where(clause="deleted_at is NULL")
public class ChatRoom {

    @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
    @Column(name="room_id")
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name="room_type", nullable = false, length=100)
    private RoomType roomType;

    @Column(name="room_title")
    private String roomTitle;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="owner_id")
    private User owner;

    @Column(name="last_message_id")
    private Long lastMessageId;

    @Column(name="member_count", nullable = false)
    private int memberCount = 0;

    @Column(name="created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name="updated_at", nullable = false)
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    @PrePersist
    public void onCreate(){
        this.createdAt = LocalDateTime.now();
    }

    public static ChatRoom create(User owner, String roomTitle, RoomType roomType, int memberCount){
        ChatRoom room = new ChatRoom();
        room.roomType = roomType;
        room.owner = owner;
        room.memberCount = 1;
        room.roomTitle = roomTitle;

        return room;
    }

    public void updateLastMessage(Long lastMessageId){
        this.lastMessageId = lastMessageId;
    }




}
