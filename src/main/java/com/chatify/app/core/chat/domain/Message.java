package com.chatify.app.core.chat.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="message")
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Getter
@SQLDelete(sql = "UPDATE message SET deleted_at = NOW() WHERE message_id = ?")
@Where(clause = "deleted_at IS NULL")
public class Message {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="message_id")
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="room_id", nullable = false)
    private ChatRoom room;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="sender_id")
    private User sender;

    @Lob
    @Column(name="content")
    private String content;

    @Enumerated(EnumType.STRING)
    @Column(name="message_type", nullable = false)
    private MessageType messageType;

    @Column(name="created_at",  nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    @OneToMany(mappedBy="message", fetch=FetchType.LAZY, cascade=CascadeType.ALL, orphanRemoval = true )
    private List<MessageAttachment> attachmentList = new ArrayList<>();


    //텍스트 메시지 생성
    public static Message createTextMessage(ChatRoom room, User sender, String content){
        Message message = new Message();
        message.room = room;
        message.sender = sender;
        message.content = content;
        message.messageType = MessageType.TEXT;
        return message;
    }
    //시스템 메시지 생성(sender가 없음)
    public static Message createSystemMessage(ChatRoom room , String content){
        Message message = new Message();
        message.room = room;
        message.sender = null; //시스템은 user_id가 없음.
        message.content = content;
        message.messageType = MessageType.SYSTEM;
        return message;
    }
    // 그외 타입의 메시지 생성
    public static Message createAttachmentMessage(ChatRoom room, User sender, MessageType type, List<MessageAttachment> attachmentList){
        Message message = new Message();
        message.room = room;
        message.sender = sender;
        message.content = null;
        message.messageType = type;

        for(MessageAttachment attachment: attachmentList){
            message.addAttachment(attachment);
        }
        return message;
    }
    //연관 관계 편의 메서드
    public void addAttachment(MessageAttachment attachment){
        this.attachmentList.add(attachment);
        attachment.setMessage(this);
    }
}
