package com.yoo.securityStudy.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {

    private final UserDetailsService memberService;

    /**
     * - SecurityFilterChain << 아무 옵션 없이 적용 시 모든 페이지 접근이 허용된다.
     * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        log.info("-------------------------");
        log.info("Filter Chain");
        log.info("-------------------------");

        // 👉  Default Login form 설정
        http.formLogin(Customizer.withDefaults());

        // 👉 모든 접근 제한
        http.authorizeHttpRequests( access ->
                        access.requestMatchers("/**")
                                .authenticated()
                                .anyRequest().authenticated()
                );

        // 👉 UserDetailService 지정 - 내가 지정한 비즈니스 로직을 사용한다.
       http.userDetailsService(memberService);

        return http.build();
    }

}
