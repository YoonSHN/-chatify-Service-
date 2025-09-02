package com.chatify.app.core.system.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name="notification")
@NoArgsConstructor(access= AccessLevel.PROTECTED)
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="user_id", nullable=false)
    private User user;

    @Enumerated
    @Column(name="type", nullable=false)
    private NotificationType type;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name="payload_json")
    private String payloadJson;

    @Column(name="is_read", nullable= false)
    private boolean isRead  = false;

    @CreationTimestamp
    @Column(name="created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name="read_at")
    private LocalDateTime readAt;

    public static Notification create(User user, NotificationType type, String payloadJson){
        Notification notification = new Notification();
        notification.user = user;
        notification.type = type;
        notification.payloadJson = payloadJson;
        return notification;
    }

    public static Notification create(User user, NotificationType type){
        return create(user, type, null);
    }

    public void read(){ //읽기 처리
        if(!this.isRead){
            this.isRead = true;
            this.readAt = LocalDateTime.now();
        }

    }
}
