package com.yoo.securityStudy.config;

import com.yoo.securityStudy.entity.enums.Roles;
import com.yoo.securityStudy.security.filter.JwtFilter;
import com.yoo.securityStudy.security.handler.CustomAccessDeniedHandler;
import com.yoo.securityStudy.security.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
    // DB를 사용한 로그인을 위한 Service
    private final UserDetailsService memberService;
    // 권한 제어 핸들러
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    // 접근 제어 핸들러
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    // Jwt 필터 추가
    private  final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        log.info("-------------------------");
        log.info(" 1) Security Filter Chain");
        log.info("-------------------------");

        /*************************************************/
        /** Default Setting **/
        /*************************************************/
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
        // 👉 Security HTTP Basic 인증 ❌ - 웹 상단 알림창으로 로그인이 뜨는 것 방지
        http.httpBasic(AbstractHttpConfigurer::disable);
        // 세션 관련 설정  -  "SessionCreationPolicy.STATELESS" 스프링시큐리티가 생성하지도않고 기존것을 사용하지도 않음
        http.sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 👉 접근 제어
        http.authorizeHttpRequests( access ->{
            // 👍 인증이 되지 않은자만 허용
            access.requestMatchers("/signUp").anonymous();
            // 👍 전체 접근 허용
            access.requestMatchers("/all").permitAll();
            // 👍 hasAnyRole를 사용해서 다양한 권한으로 접근 가능
            access.requestMatchers("/user").hasAnyRole(Roles.USER.name(), Roles.MANAGER.name(),Roles.ADMIN.name());
            access.requestMatchers("/manager").hasAnyRole(Roles.MANAGER.name(),Roles.ADMIN.name());
            // 👍 hasRole을 사용하면 단일 권한 지정
            access.requestMatchers("/admin").hasRole(Roles.ADMIN.name());
            // ℹ️ 순서가 중요하다 최상의 경우 에러 발생
            //     어떠한 요청에도 검사 시작 - 로그인만 된다면 누구든 접근 가능
            access.anyRequest().authenticated();
        });

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

       // 👉 필터 순서 번경
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
       
        return http.build();
    }


    /**
     * Security - Custom Bean 등록
     * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring()
                // 로그인 접근은 누구나 허용
                .requestMatchers(HttpMethod.POST,"/member/login")
                // Spring Boot의 resources/static 경로의 정적 파일들 접근 허용
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

}
