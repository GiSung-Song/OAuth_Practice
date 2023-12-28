package com.example.study.config;

import org.springframework.boot.web.servlet.view.MustacheViewResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * viewResolver => mustache로 변경
 */

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {

        MustacheViewResolver resolver = new MustacheViewResolver();
        resolver.setCharset("UTF-8"); //인코딩 UTF-8
        resolver.setContentType("text/html;charset=UTF-8");
        resolver.setPrefix("classpath:/templates/");
        resolver.setSuffix(".html"); //html 파일을 mustache로 인식

        registry.viewResolver(resolver);
    }
}
