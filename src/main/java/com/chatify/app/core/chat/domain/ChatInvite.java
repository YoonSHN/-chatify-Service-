package com.chatify.app.core.chat.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Table(name="chat_invite")
public class ChatInvite {

    @Id @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="invite_id")
    private Long id;

    @JoinColumn(name="room_id", nullable = false)
    @ManyToOne(fetch=FetchType.LAZY)
    private ChatRoom chatRoom;

    @JoinColumn(name="inviter_id")
    @ManyToOne(fetch=FetchType.LAZY)
    private User inviter;

    @JoinColumn(name="invitee_id")
    @ManyToOne(fetch=FetchType.LAZY)
    private User invitee;

    @Enumerated(EnumType.STRING)
    @Column(name="status", nullable = false)
    private InviteStatus inviteStatus;

    @Column(name="created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name="expires_at")
    private LocalDateTime expiresAt;

    public static ChatInvite create(ChatRoom room, User inviter, User invitee, LocalDateTime expiresAt){
        ChatInvite invite = new ChatInvite();
        invite.chatRoom = room;
        invite.inviter = inviter;
        invite.invitee = invitee;

        return invite;
    }

    @PrePersist
    public void onCreate(){
        this.createdAt = LocalDateTime.now();
        this.inviteStatus = InviteStatus.PENDING;
        this.expiresAt = this.createdAt.plusDays(3); //시작일 로부터 3일후면 만료
    }
    public void accept(){
        this.inviteStatus = InviteStatus.ACCEPTED;
    }
    public void decline(){
        this.inviteStatus = InviteStatus.DECLINED;
    }
}
