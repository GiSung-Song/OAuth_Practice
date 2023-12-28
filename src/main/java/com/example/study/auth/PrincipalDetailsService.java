package com.example.study.auth;

import com.example.study.model.User;
import com.example.study.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login")
 *  /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC(@Service)되어 있는 loadUserByUsername 함수가 실행
 */

@Service
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 시큐리티 Session (내부 Authentication (내부 UserDetails))
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        log.info("user : " + userEntity);

        if (userEntity != null) {
            return new PrincipalDetails(userEntity);
        }

        return null;
    }
}
