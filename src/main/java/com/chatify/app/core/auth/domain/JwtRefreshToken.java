package com.chatify.app.core.auth.domain;

import com.chatify.app.core.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Table(name="jwt_refresh_token")
@NoArgsConstructor(access= AccessLevel.PROTECTED)
public class JwtRefreshToken {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="user_id", nullable=false)
    private User user;

    @Column(name="token_hash", nullable=false, length= 64)
    private String tokenHash;

    @CreationTimestamp
    @Column(name="issued_at", nullable=false, updatable=false)
    private LocalDateTime issuedAt;

    @Column(name="expires_at", nullable=false)
    private LocalDateTime expiresAt;

    @Column(name="device_id", length = 100)
    private String deviceId;

    @Column(name="ip_address", length=45)
    private String ipAddress;

    public static JwtRefreshToken create(User user, String tokenHash, LocalDateTime expiresAt, String deviceId, String ipAddress){
        JwtRefreshToken token = new JwtRefreshToken();
        token.user = user;
        token.tokenHash = tokenHash;
        token.expiresAt = expiresAt;
        token.deviceId = deviceId;
        token.ipAddress = ipAddress;
        return token;
    }
    public static JwtRefreshToken create(User user, String tokenHash, LocalDateTime expiresAt){
        return create(user, tokenHash, expiresAt, null,null);
    }
}
