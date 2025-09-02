package com.chatify.app.core.chat.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Table(name="message_attachment")
@SQLDelete(sql="UPDATE message_attachment SET deleted_at = NOW() WHERE attachment_id = ?")
@Where(clause="deleted_at IS NULL")
public class MessageAttachment {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="attachment_id")
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="message_id", nullable = false)
    private Message message;

    @Enumerated(EnumType.STRING)
    @Column(name="kind", nullable = false)
    private MessageType kind;  // IMAGE, FILE, VIDEO, AUDIO

    @Column(name="file_path", length = 255, nullable = false)
    private String filePath;

    @Column(name="mime_type", length=100)
    private String mimeType;

    @Column(name="size_bytes")
    private Long sizeBytes;

    @CreationTimestamp
    @Column(name="created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    public static MessageAttachment create(MessageType type, String filePath, String mimeType, Long sizeBytes){
        MessageAttachment attachment = new MessageAttachment();
        attachment.kind = type;
        attachment.filePath = filePath;
        attachment.mimeType = mimeType;
        attachment.sizeBytes = sizeBytes;
        return attachment;
    }
    public static MessageAttachment create(MessageType type, String filePath){
        return create(type, filePath, null, null);
    }
    //연관 관계 편의 메서드
    protected void setMessage(Message message) {
        this.message = message;
    }
}
