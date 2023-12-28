package com.example.study.controller;

import com.example.study.auth.PrincipalDetails;
import com.example.study.model.User;
import com.example.study.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails principalDetails) {

        log.info("/test/login ================");
        PrincipalDetails principalDetail = (PrincipalDetails) authentication.getPrincipal();
        log.info("principalDetails.getUser() : {}", principalDetail.getUser());
        log.info("userDetails : {}", principalDetails.getUser());
        log.info("/test/login ================");

        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth) {

        log.info("/test/login ================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("principalDetails.getUser() : {}", oAuth2User.getAttributes());
        log.info("oauth2User : {}", oauth.getAttributes());
        log.info("/test/login ================");

        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping(value = {"", "/"})
    public String index() {

        //머스테치 기본폴더 src/main/resources/
        //뷰 리졸버 설정 : templates (prefix), suffix (.mustache)
        return "index"; // src/main/resources/templates/index.mustache
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {

        log.info("principalDetails : {}", principalDetails.getUser());

        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    //스프링 시큐리티가 해장 주소를 낚아챔 -> securityConfig 파일 생서 후 작동안함.
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("user : ", user);

        user.setRole("ROLE_USER");

        String rawPassword = user.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword);

        user.setPassword(encPassword); //비밀번호 암호화
        userRepository.save(user); //security 로그틴 불가 -> 패스워드 암호화 필요

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
}
