package com.chatify.app.core.chat.domain;

import com.chatify.app.core.user.domain.BlockUserId;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@Embeddable
@Getter
@NoArgsConstructor(access= AccessLevel.PROTECTED)
@AllArgsConstructor
public class MessageReadId implements Serializable {

    @Column(name="message_id")
    private Long messageId;

    @Column(name="user_id")
    private Long userId;

    @Override
    public boolean equals(Object o){
        if(this==o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        MessageReadId that = (MessageReadId)o ;
        return Objects.equals(messageId, that.messageId) && Objects.equals(userId, that.userId);
    }
    @Override
    public int hashCode(){
        return Objects.hash(messageId, userId);
    }


}
