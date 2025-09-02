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
@Table(name="reported_message")
public class ReportedMessage {

    @Id @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="report_id")
    private Long reportId;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="message_id")
    private Message message;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="reporter_id")
    private User reporter;

    @Column(name="reason", nullable = false)
    @Enumerated(EnumType.STRING)
    private ReportReason reportReason;

    @Column(name="status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ReportStatus status;

    @CreationTimestamp
    @Column(name="created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name="finished_at")
    private LocalDateTime finishedAt; //처리시각

    public static ReportedMessage create(Message message, User reporter, ReportReason reportReason){
        ReportedMessage reportedMessage = new ReportedMessage();
        reportedMessage.message = message;
        reportedMessage.reporter = reporter;
        reportedMessage.reportReason = reportReason;
        reportedMessage.status = ReportStatus.OPEN;

        return reportedMessage;
    }
}
