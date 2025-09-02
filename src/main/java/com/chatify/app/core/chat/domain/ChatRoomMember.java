package com.chatify.app.core.chat.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Table(name = "chat_room_member")
public class ChatRoomMember {

    @EmbeddedId
    private ChatRoomMemberId id;

    @ManyToOne(fetch=FetchType.LAZY)
    @MapsId("roomId")
    @JoinColumn(name = "room_id")
    private ChatRoom chatRoom;

    @ManyToOne(fetch=FetchType.LAZY)
    @MapsId("userId")
    @JoinColumn(name="user_id")
    private User user;

    @Column(name="role", nullable = false)
    @Enumerated(EnumType.STRING)
    private MemberRole role;

    @Column(name="nickname_in_room" , length=50)
    private String nicknameInRoom;

    @Column(name="joined_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime joinedAt; //최초 가입일은 변경되지 않도록 유지

    @Column(name="last_read_message_id")
    private Long lastReadMessageId;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    public static ChatRoomMember create(ChatRoom chatRoom, User user){
        ChatRoomMember member = new ChatRoomMember();
        member.id = new ChatRoomMemberId(chatRoom.getId(), user.getId());
        member.role = MemberRole.MEMBER;
        member.user = user;
        member.chatRoom = chatRoom;
        return member;
    }
    public void leave(){
        this.deletedAt = LocalDateTime.now();  //소프트 삭제
    }

    public void rejoin(){
        this.deletedAt = null;
    }
}
