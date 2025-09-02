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
public class ChatRoomMemberId implements Serializable {

    @Column(name="room_id")
    private Long roomId;

    @Column(name="user_id")
    private Long userId;

    @Override
    public boolean equals(Object o){
        if(this==o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        ChatRoomMemberId that = (ChatRoomMemberId)o ;
        return Objects.equals(roomId, that.roomId) && Objects.equals(userId, that.userId);
    }
    @Override
    public int hashCode(){
        return Objects.hash(roomId, userId);
    }
}
