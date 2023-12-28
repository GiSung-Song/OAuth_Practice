package com.example.study.config;

import com.example.study.config.auth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 로그인 완료 된 뒤 후처리 필요,
 * 1. 코드받기(인증) -> 정상적인 로그인, 2.엑세스토큰(권한), 3.사용자 프로필 가져오기
 * 4-1. 받아온 정보를 토대로 회원가입을 지동으로 진행
 */

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableMethodSecurity(securedEnabled = true, //secured 어노테이션 활성화 -> 메서드에 @Secured(ROLE_~) 작성 시 적용됨
        prePostEnabled = true)  //preAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
               .csrf(CsrfConfigurer::disable)
               .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/user/**").authenticated()
                       .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                       .requestMatchers("/admin/**").hasRole("ADMIN")
                       .anyRequest().permitAll())
               .formLogin(login -> login
                       .loginPage("/loginForm")
                       .loginProcessingUrl("/login") // /login 주소 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행
                       .defaultSuccessUrl("/"))
               .oauth2Login(oauth -> oauth
                       .loginPage("/loginForm")
                       .userInfoEndpoint(config -> config
                               .userService(principalOauth2UserService))); //로그인 후 데이터에대한 후처리되는 서비스

       return http.build();
    }
}
