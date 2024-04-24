package com.yoo.securityStudy.config;

import com.yoo.securityStudy.security.handler.CustomAccessDeniedHandler;
import com.yoo.securityStudy.security.handler.CustomAuthFailureHandler;
import com.yoo.securityStudy.security.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {

    private final UserDetailsService memberService;

    // 권한 제어 핸들러
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    // 접근 제어 핸들러
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    // 인증 제어 핸들러
    private final CustomAuthFailureHandler customAuthFailureHandler;

    /**
     * - SecurityFilterChain << 아무 옵션 없이 적용 시 모든 페이지 접근이 허용된다.
     * */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        log.info("-------------------------");
        log.info("Filter Chain");
        log.info("-------------------------");

        // 👉 CSRF 사용 ❌
        http.csrf(csrf -> csrf.disable());
        // 👉 CORS 설정
        http.cors(cors->{
            /**
             * 참고 : https://velog.io/@juhyeon1114/Spring-security%EC%97%90%EC%84%9C-CORS%EC%84%A4%EC%A0%95%ED%95%98%EA%B8%B0
             *    - 설정 클래스를 만든 후 주입해주면 Cors 설정이 한번에 가능함
             * */
            // cors.configurationSource(CorsConfigurationSource)
        });

        // 👉  Default Login form 설정
        http.formLogin(login->login.loginProcessingUrl("/login")
                .failureHandler(customAuthFailureHandler));

        // 👉 기본 설정 로그인 form 사용 ❌
        http.formLogin(login->login.loginProcessingUrl("/login")
                .failureHandler(customAuthFailureHandler));
        // 👉 Security HTTP Basic 인증 ❌ - 웹 상단 알림창으로 로그인이 뜨는 것 방지
        http.httpBasic(AbstractHttpConfigurer::disable);

        // 👉 모든 접근 제한
        http.authorizeHttpRequests( access ->
                        access.requestMatchers("/**")
                                .authenticated()
                                .anyRequest().authenticated()
                );

        // 👉 UserDetailService 지정 - 로그인 시 내가 지정한 비즈니스 로직을 사용한다.
       http.userDetailsService(memberService);

        // Custom Exception Handling
        http.exceptionHandling(handling ->
               handling
                    // ✨ Access Denied Handling
                    .accessDeniedHandler(customAccessDeniedHandler)
                     // ✨ AuthenticationEntryPoint
                    .authenticationEntryPoint(customAuthenticationEntryPoint)
        );

        return http.build();
    }


    /**
     * Security - Custom Bean 등록
     * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring()
                // Login 접근 허용
                .requestMatchers(HttpMethod.POST,"/member/login")
                // Spring Boot의 resources/static 경로의 정적 파일들 접근 허용
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

}
