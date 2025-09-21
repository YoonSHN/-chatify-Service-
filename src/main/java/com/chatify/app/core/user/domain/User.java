package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

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

    // User가 삭제되면 관련된 UserImage도 함께 삭제되도록 설정
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserImage> userImages = new ArrayList<>();



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
    public User updateSocialProfile(String name) {
        if (this.getUserProfile() != null) {
            this.getUserProfile().updateName(name); // UserProfile의 이름 업데이트 메서드 호출
        }
        return this;
    }
    // 연관관계 편의 메서드: User에 이미지를 추가할 때 사용
    public void addUserImage(UserImage userImage) {
        this.userImages.add(userImage);
    }



}
