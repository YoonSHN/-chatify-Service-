package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Table(name="user")
@SQLDelete(sql = "UPDATE user SET deleted_at = now() WHERE user_id = ?")
@Where(clause="deleted_at IS NULL")
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="user_id")
    private Long id;

    @OneToOne(mappedBy="user", cascade = CascadeType.ALL, orphanRemoval=true)
    private UserProfile userProfile;

    @OneToOne(mappedBy="user", cascade = CascadeType.ALL, orphanRemoval=true)
    private UserSettings userSettings;

    @Column(name="email", nullable = false, unique = true,length = 100)
    private String email;

    @Column(name="password", length=255)
    private String password;

    @Column(name="phone_number", unique=true, length=20)
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    @Column(name="status", nullable = false)
    private UserStatus status;

    @Column(name="last_seen_at")
    private LocalDateTime lastSeenAt;

    @Column(name="created_at", nullable=false, updatable=false)
    private LocalDateTime createdAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    @Builder
    public User(String email, String password, String phoneNumber) {
        this.password = password;
        this.email = email;
        this.phoneNumber = phoneNumber;
    }

    public void setUserProfile(UserProfile userProfile){
        this.userProfile = userProfile;
    }

    public void setUserSettings(UserSettings userSettings){
        this.userSettings = userSettings;
    }

    @PrePersist
    protected void onCreate(){
        this.createdAt = LocalDateTime.now();
        this.status = UserStatus.ACTIVE;
    }

}
