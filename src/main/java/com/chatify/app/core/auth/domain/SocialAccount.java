package com.chatify.app.core.auth.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@Getter
@Table(name="social_account",
    uniqueConstraints= {
        @UniqueConstraint(
                name = "social_account_uk",
                columnNames={"provider", "provider_user_id"}
        )
    })
public class SocialAccount {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name="social_id")
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name="provider", nullable = false)
    private Provider provider;

    @Column(name="provider_user_id", nullable = false, length =255)
    private String providerUserId; //소셜 서비스에서 제공하는 고유 ID

    @CreationTimestamp
    @Column(name="connected_at", nullable=false, updatable=false)
    private LocalDateTime connectedAt;

    public static SocialAccount create(User user, Provider provider, String providerUserId){
        SocialAccount account = new SocialAccount();
        account.user = user;
        account.provider = provider;
        account.providerUserId = providerUserId;
        return account;
    }

}
