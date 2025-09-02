package com.chatify.app.core.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name="user_image")
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@SQLDelete(sql = "UPDATE user_image SET deleted_at = now() WHERE user_image_id = ?")
@Where(clause="deleted_at IS NULL")
public class UserImage {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="user_image_id")
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="user_id", nullable=false)
    private User user;

    @Column(name="image_url", nullable=false)
    private String imageUrl;

    @Column(name="image_type", nullable=false)
    @Enumerated(EnumType.STRING)
    private ImageType imageType;

    @Column(name="created_at", updatable=false, nullable=false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name="deleted_at")
    private LocalDateTime deletedAt;

    public static UserImage create(User user, String imageUrl, ImageType imageType){
        //Not Null 조건이 많음.
        UserImage userImage = new UserImage();
        userImage.user = user;
        userImage.imageUrl = imageUrl;
        userImage.imageType = imageType;

        return userImage;
    }
}
