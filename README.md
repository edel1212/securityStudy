# Spring Security Study

### Security Depenency

- 의존성을 추가하는 순간부터 모든 요청은 Scurity의 Filter를 거치게 된다.
  - 따라서 모든 요청은 Security에서 기본적으로 제공되는 LoginForm으로 이동된다.
    - 계정 및 비밀번호는 로그에 써 있다.

```java
dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-security'
	testImplementation 'org.springframework.security:spring-security-test'
}
```

### 기본 Security 설정

- SpringBoot 버전이 올라가면서 Security 설정 방법이 변경되었다.
  - 작성일 기준 버전 `3.2.3`버전
- 지정 클래스는 Bean Scan 대상에 추가 해줘야한다.
  - `@Component` 어노테이션 사용
- `SecurityFilterChain`를 구현하는 메서드를 생성한 후 Bean에 추가해준다.

  - 생성 이후 부터는 모든 요청에 대한 접근이 **허용**으로 변경된다.

  ```java
  @Component
  @Log4j2
  public class SecurityConfig {

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
          //http.formLogin(Customizer.withDefaults());

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
  ```

## TODO List

- DB 계정 관리
  - 권한별 접근
- 커스텀 핸들러 적용
- jwt
  - Refresh token
