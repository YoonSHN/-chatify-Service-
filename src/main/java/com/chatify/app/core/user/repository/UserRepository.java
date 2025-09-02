package com.chatify.app.core.user.repository;

import com.chatify.app.core.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    //이메일로 회원 찾기
    Optional<User> findUserByEmail(String email);

    //이메일로 회원이 존재하는지 찾기
    boolean existsUserByEmail(String email);


}
