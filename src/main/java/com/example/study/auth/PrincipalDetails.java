package com.example.study.auth;

import com.example.study.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행
 * 로그인 진행이 완료가 되면 시큐리티 session 생성 ( Security ContextHolder)
 * 오브젝트 타입 => Authentication 타입 객체
 * Authentication 안에 User 정보가 있어야함
 * User 오브젝트 타입 => UserDetails 타입 객체
 * Security Session => Authentication => UserDetails(PrincipalDetails)
 */

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //컴포지션
    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User 권한 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(() -> {return user.getRole();});

        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
