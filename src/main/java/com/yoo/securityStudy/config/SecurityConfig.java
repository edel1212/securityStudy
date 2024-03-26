package com.yoo.securityStudy.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
@Log4j2
public class SecurityConfig {

    // 👉 Password를 인코딩 Bean 주입
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

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


        return http.build();
    }

}
