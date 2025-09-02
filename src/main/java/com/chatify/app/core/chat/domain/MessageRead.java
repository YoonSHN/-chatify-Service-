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
@Table(name="message_read")
public class MessageRead {

    @EmbeddedId
    private MessageReadId id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="message_id")
    @MapsId("messageId")
    private Message message;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="user_id")
    @MapsId("userId")
    private User user;

    @CreationTimestamp
    @Column(name="read_at", nullable=false, updatable=false)
    private LocalDateTime readAt;

    public MessageRead(Message message, User user){
        this.id = new MessageReadId(message.getId(), user.getId());
        this.message = message;
        this.user = user;
    }

}
