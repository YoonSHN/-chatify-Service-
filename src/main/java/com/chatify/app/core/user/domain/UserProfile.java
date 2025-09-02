package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.Where;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Table(name="user_profile")
@Getter
@SQLDelete(sql = "UPDATE user_profile SET deleted_at = NOW() WHERE user_id = ?")
@Where(clause = "deleted_at IS NULL")
public class UserProfile {

    @Id
    @Column(name="user_id")
    private Long id;

    @OneToOne(fetch=FetchType.LAZY)
    @MapsId
    @JoinColumn(name="user_id")
    private User user;

    @Column(name="real_name", length=30)
    private String realName;

    @Column(name="birthday")
    private LocalDate birthday;

    @Column(name="profile_message", length=255)
    private String profileMessage;

    @Column(name="nickname", length=30)
    private String nickname;

    @CreationTimestamp
    @Column(name="created_at", nullable=false, updatable=false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name="updated_at", nullable=false)
    private LocalDateTime updatedAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @PrePersist
    protected void onCreate(){
        this.createdAt = LocalDateTime.now();
    }

    public static UserProfile create(User user, String realName, LocalDate birthday){
        UserProfile userProfile = new UserProfile();
        userProfile.user = user;
        userProfile.realName = realName;
        userProfile.birthday = birthday;
        return userProfile;
    }
    //프로필 화면에 표시 될 이름(real_name or nickname)
    public String getDisplayName(){
        return (this.nickname != null && !this.nickname.isBlank() ? this.nickname : this.realName);
    }

}
