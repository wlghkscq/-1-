package com.sparta.springcore.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@EnableGlobalMethodSecurity(securedEnabled = true) // @Secured 어노테이션 활성화
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // 암호화 알고리즘
    @Bean
    public BCryptPasswordEncoder encodePassword(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web){
        // h2-console 사용에 대한 허용 ( CSRF, FrameOptions 무시)
        web
                .ignoring()
                .antMatchers("/h2-console/**");
    }


    @Override // 재정의
    protected void configure(HttpSecurity http) throws Exception {

        // 회원 관리 처리 API (POST /user/**)에 대해 CSRF 무시
//        http.csrf()
//                .ignoringAntMatchers("/user/**");
        http.csrf().disable(); // 일단 테스트를 위해 csrf 비활성화


        http.authorizeRequests()
                // image 폴더를 login 없이 허용
                .antMatchers("/images/**").permitAll()

                // css 폴더를 login 없이 허용
                .antMatchers("/css/**").permitAll()

                // 회원 관리 처리 API 전부를 login 없이 허용
                .antMatchers("/user/**").permitAll()

                // 그 외 어떤 요청이든 '인증' 과정을 거치겠다.
                .anyRequest().authenticated()
                .and()
                    // 로그인 기능은 인증과정없이 허용
                    .formLogin()

                    // 로그인 View 제공 (GET /user/login)
                    .loginPage("/user/login")

                    // 로그인 처리 (POST / user/login)
                    .loginProcessingUrl("/user/login")

                    // 로그인 처리후 성공 시 URL
                    .defaultSuccessUrl("/")

                    // 로그인 처리후 실패시 URL
                    .failureUrl("/user/login?error") // 로그인 실패시 "/~ " 해당페이지로 이동
                    .permitAll()
                .and()
                    // 로그아웃 기능은 인증과정없이 허용
                    .logout()

                    // 로그아웃 URL
                    .logoutUrl("/user/logout")
                    .permitAll()

                .and()
                    .exceptionHandling()
                    // " 접근 불가 " 페이지 URL 설정
                    .accessDeniedPage("/forbidden.html");

    }

}
