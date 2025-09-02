package com.chatify.app.core.user.domain;

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
public class BlockUserId implements Serializable {

    @Column(name="blocker_id")
    private Long blockerId;

    @Column(name="blocked_id")
    private Long blockedId;

    @Override
    public boolean equals(Object o){
        if(this==o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        BlockUserId that = (BlockUserId)o ;
        return Objects.equals(blockerId, that.blockerId) && Objects.equals(blockedId, that.blockedId);
    }
    @Override
    public int hashCode(){
        return Objects.hash(blockerId, blockedId);
    }


}
