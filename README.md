# Spring Security Study

### Security
Depenency

- 의존성을 추가하는 순간부터 모든 요청은 Scurity의 Filter를 거치게 된다.
  - 따라서 모든 요청은 Security에서 기본적으로 제공되는 LoginForm으로 이동된다.
    - 계정 및 비밀번호는 로그에 써 있다.

```groovy
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
- 함수형 인터페이스를 사용하여 옵션을 적용해준다.
  - 이전 `체이닝 -> 함수형`으로 변경되었다.
-  `SecurityFilterChain`를 구현한 메서드내의 매개변수인  HttpSecurity 객체에 옵션을 더하는 식으로 설정을 한다.
-  `WebSecurityCustomizer`를 구현한 메서드내에서 Security 필터에서 제외할 요청을 지정 가능하다
   - 정적파일을 사용하는 경우에는 꼭 해당 설정해주자.
- 예시 코드 	
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
          // 👉 세션 관련 설정  -  "SessionCreationPolicy.STATELESS" 스프링시큐리티가 생성하지도않고 기존것을 사용하지도 않음
          http.sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
          
          // 👉 모든 접근 제한
          http.authorizeHttpRequests( access ->{
              // 어떠한 요청에도 검사 시작
              access.anyRequest().authenticated();
          });

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

### 예외 핸들러 설정

- `AuthenticationEntryPoint` 설정
  - 인증이 실패했을 때 사용자를 리디렉션하거나 에러 메시지를 반환하는 역할을 담당함
    - 인증 실패 처리: 사용자가 인증되지 않았거나, 인증 정보가 잘못되었을 때 호출됩니다.
    - 리디렉션: 웹 애플리케이션에서는 인증되지 않은 사용자를 로그인 페이지로 리디렉션하는 것이 일반적입니다. AuthenticationEntryPoint를 사용하여 이러한 리디렉션을 설정할 수 있습니다
    - 에러 메시지 반환: 인증이 실패하면 사용자에게 에러 메시지나 HTTP 상태 코드를 반환하여 문제의 원인을 알릴 수 있습니다.
  - 사용 방법
    - `AuthenticationEntryPoint`를 구현한 클래스 제작
    - Bean Scan 대상에 올려주기 위해 `@Component`를 추가해주자
      ```java
      @Log4j2
      @Component
      public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            log.info("- Custom Authentication Entry PointHandler 접근 -");
            var objectMapper = new ObjectMapper();
            int scUnauthorized = HttpServletResponse.SC_UNAUTHORIZED;
            response.setStatus(scUnauthorized);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .code(scUnauthorized)
                    .message("예외 메세지 등록")
                    .build();
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
      }
      ```
- `AccessDeniedHandler` 설정
  - 인증에 실패했을 경우 처리를 담당한다.
  - 사용 방법
    - `AccessDeniedHandler`를 구현한 클래스 제작
    - Bean Scan 대상에 올려주기 위해 `@Component`를 추가해주자
      ```java
      @Log4j2
      @Component
      public class CustomAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
          log.info("- Custom Access Denied Handler 접근 -");
          var objectMapper = new ObjectMapper();
          int scUnauthorized = HttpServletResponse.SC_UNAUTHORIZED;
          response.setStatus(scUnauthorized);
          response.setContentType(MediaType.APPLICATION_JSON_VALUE);
          response.setCharacterEncoding(StandardCharsets.UTF_8.name());
          ErrorResponse errorResponse = ErrorResponse.builder()
                  .code(scUnauthorized)
                  .message("접근 권한이 없습니다.")
                  .build();
          response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
      }
      ```    
- `SecurityConfig` 설정 
  - 의존성 주입 후 `exceptionHandling()`에 등록
    ```java
    @Component
    @RequiredArgsConstructor
    @Log4j2
    public class SecurityConfig {
    
      // 접근 제어 핸들러
      private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    
      @Bean
      public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    
    
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

- `AuthFailureHandler` 설정
  - 해당 핸들러는 로그인 실패 시 핸들링 하는 핸들러이다. - ℹ️ 단 ! ***jwt 를사용할 경우 사용이 불가능하다.***
  - 내부 Form 설정을 사용할 경우만 사용이 가능하다
  - 사용 방법
    - `SimpleUrlAuthenticationFailureHandler`를 상속한(`extends`) 클래스 제작 또는 `AuthenticationFailureHandler`를 구현한(`implements`) 클래스를 제작
      - `SimpleUrlAuthenticationFailureHandler`를 사용하는 이유는?
        - `AuthenticationFailureHandler`를 구한현 클래스이므로 같은 기능을 작동한다.
        - SimpleUrl을 사용할 경우 `setDefaultFailureUrl()`를 사용하여 이동할 URL을 지정 가능하다.
    - Bean Scan 대상에 올려주기 위해 `@Component`를 추가해주자
       ```java
       @Log4j2
       @Component
       public class CustomAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {
         @Override
         public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
           log.info("- Custom Auth Failure Handler 접근 -");
           var objectMapper = new ObjectMapper();
           String errorMessage;
           if (exception instanceof BadCredentialsException) {
             errorMessage = "아이디와 비밀번호를 확인해주세요.";
           } else if (exception instanceof InternalAuthenticationServiceException) {
             errorMessage = "내부 시스템 문제로 로그인할 수 없습니다. 관리자에게 문의하세요.";
           } else if (exception instanceof UsernameNotFoundException) {
             errorMessage = "존재하지 않는 계정입니다.";
           } else {
             errorMessage = "알 수없는 오류입니다.";
           }
           ErrorResponse errorResponse = ErrorResponse.builder()
                   .code(HttpServletResponse.SC_UNAUTHORIZED)
                   .message(errorMessage)
                   .build();
           // 응답의 문자 인코딩을 UTF-8로 설정
           response.setCharacterEncoding(StandardCharsets.UTF_8.name());
           response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
         }
       }
       ```   
- `SecurityConfig` 설정
  - 의존성 주입 후 `formLogin()`내 함수 등록 `failureHandler(customAuthFailureHandler)`
  - ℹ️ 중요 확인 사항
    - `loginProcessingUrl()`에 등록된 주소는 Controller가 없다 action="주소"에 해당되는 값이다.
    - `ignoring()`에 LoginProcessingUrl을 등록하면 안된다. 
      - Spring Security의 필터에서 제외 되기에 FailureHandler를 등록해도 제외된다.
      - 사용 했던 이유는 로그인 페이지는 접근이 무조건 가능해야한다 생각함
        - 하지만 `formLogin()`에서 `loginProcessingUrl()`를 지정하면 누구나 접근이 가능 했음..!
  - 
    ```java
    @Component
    @RequiredArgsConstructor
    @Log4j2
    public class SecurityConfig {
    
      // 인증 실패 제어 핸들러
      private final CustomAuthFailureHandler customAuthFailureHandler;
    
      @Bean
      public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    
        // 👉 로그인을 사용할 loginProcessingUrl을  Front단 action 주소임 - 컨트롤러 없음 설정해준다.
        http.formLogin(login->login.loginProcessingUrl("/member/login")
                .failureHandler(customAuthFailureHandler));      
    
        return http.build();
      }
    
      /**
       * Security - Custom Bean 등록
       * */
      @Bean
      public WebSecurityCustomizer webSecurityCustomizer(){
          return web -> web.ignoring()
                  /*********************************************/
                  /** 아래 주석 내용떄문에 삽질함 ... */
                  /*********************************************/
                  // Login 접근 허용
                  //.requestMatchers(HttpMethod.POST,"/member/login")
        
                  // Spring Boot의 resources/static 경로의 정적 파일들 접근 허용
                  .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
      }
    }    
    ```  

### `AuthFailureHandler`를 사용하지 않고 계정 및 비밀번호 예외 처리 방법
- 방법은 크게 2가지가 있다.
  - `AbstractAuthenticationProcessingFilter`를 상속한 클래스를 만든 후 Filter 순서를 바꾼다.
  - `@RestControllerAdvice`를 지정한 ExceptionController를 구현하여 처리하는 방법
- ✨ `AbstractAuthenticationProcessingFilter` 방법
  - Spring Security의 필터의 순서를 바꿔서 진행하는 방법이다.
    - Security의 사용 방법에서 크게 벗어나지 않지만 가독성이 떨어지는 측면이 있다.
    - 로그인 시 파라미터를 JSON으로 받기 위해 추가적인 설정이 필요하다.
      - `HttpServletRequest request`에서 `getParameter()`를 사용하는 form 방식을 사용한다면 크게 불편한 문제는 아니다.
  - 사용 방법
    - `AbstractAuthenticationProcessingFilter`를 상속하는 Class 생성
      - ✏️ 중요 
        - Bean 등록 대상이 아닌 객체 생성을 통해 주입되는 Class 이므로 `@Component`와 같은 어노테이션은 불필요
        - 생성자 메서드의 `super(defaultFilterProcessesUrl);`에 전송되는 파라미터 값은 로그인 `action url path`이다 
      - `Authentication attemptAuthentication()`메서드 구현은 필수이다
        - 로그인 관련 메서드이다.
      - 성공 시, 실패 시 핸들링을 해주기 위해서는 각각 필요한 메서드를 `@Override`해줘야한다.
        - 성공 : `void successfulAuthentication()`
        - 실패 : `void unsuccessfulAuthentication()`
- `AbstractAuthenticationProcessingFilter`상속 구현 코드
  ```java
  public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
  
      private JwtUtil jwtUtil;
  
      // ✨ 부모Class가 생성자가 있기에 super()를 통해 url을 주입
      protected JwtLoginFilter(String defaultFilterProcessesUrl, JwtUtil jwtUtil) {
          super(defaultFilterProcessesUrl); // 👉 여기에 입력되는것이 login path이다
          this.jwtUtil = jwtUtil;
      }
  
      // 👉 인증 처리 - 필수 구현 메서드
      @Override
      public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
          // ✨ 필요에 맞는 parameter명을 맞춰서 사용해주자
          String email = request.getParameter("아이디 파라미터명");
          String pw    = request.getParameter("패스워드 파라미터명");
          return null;
      }시
  
      // 성공 시
      @Override
      protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
          // 아래의 정보를 통해 성공 로직을 채울 수 있음
          authResult.getAuthorities();
          authResult.getPrincipal();
          super.successfulAuthentication(request, response, chain, authResult);
      }
  
      // 실패 시
      @Override
      protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
          // TODO Fail 시 설정
          super.unsuccessfulAuthentication(request, response, failed);
      }
  
  }
  ```
- `SecurityConfig` 설정
  ```java
  
  @Configuration
  @RequiredArgsConstructor
  @Log4j2
  public class SecurityConfig {
      // 인증 실패 제어 핸들러
      private final JwtUtil jwtUtil;
  
      @Bean
      public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
          // 👉  필터의 순서를 변경해준다.
          http.addFilterBefore(new JwtLoginFilter("/member/login", jwtUtil)
                  // 비밀번호 필터보다 먼저 실행한다.
                  , UsernamePasswordAuthenticationFilter.class );
          return http.build();
      }
  
  }
  ```

- ✨ `@RestControllerAdvice` 방법
  - 간단하게 발생하는 예외를 Catch하여 반환하는 방법이다.
  - 사용 방법
    - `ExceptionController` 구현 코드
        ```java
        @RestControllerAdvice
        @Log4j2
        public class ExceptionController {
    
            // 💬 BadCredentialsException 발생 시 해당 Controller로 반환
            @ExceptionHandler(BadCredentialsException.class)
            public ResponseEntity badCredentialsException(BadCredentialsException e) {
                ErrorResponse errorResponse = ErrorResponse.builder()
                        .code(HttpServletResponse.SC_UNAUTHORIZED)
                        .message("아이디와 비밀번호를 확인해주세요.")
                        .build();
                log.error("----------------------");
                log.info(e.getMessage());
                log.error("----------------------");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
        }
        ```  

### UserDetailService 설정
- **DB를** 통해 회원을 관리하기 위해서는 꼭 필요한 설정이다.
- `UserDetailsService`를 구현한 구현체 클래스가 필요하다.
  - 해당 Interface가 구현을 강제하는 메서드인 `UserDetails loadUserByUsername()`가 인증을 진행한다.
    - `UserDetails`또한 Interface이며, 해당 Interface를 구현한 User를 반환하거나 상속한 Class를 반환해줘야한다.
      - `User`를 반환해도 괜찮지만 아이디, 패스워드, 권한 밖에 없으므로  상속을 통해 다양한 데이터를 객체로 
       담아 사용하기 위해서는 상속을 통해 사용해주자.
- ### Entity
  - 권한의 경우 Enum을 통해 Table을 생성한다.
    - `@ElementCollection(fetch = FetchType.LAZY)` 어노테이션을 통해 해당 테이블은 `회원ID, 권한`이 PK로 설정된다.
    -  `@Enumerated(EnumType.STRING)`를 통해 Enum이 숫자가 아닌 문자형태로 지정한 권한이 저장된다.
  - ⭐️ 권한 Roles
    ```java
    public enum Roles {
      USER ,
      MANAGER ,
      ADMIN ,
    }
    ```
  - ⭐️ 회원 Member
    ```java
    @Entity
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Builder
    public class Member {
      @Id
      private String id;
      
      @Column(nullable = false)
      private String password;
      
      @Column(nullable = false)
      private String name;
      
      // ⭐️ ElementCollection을 사용해줘야 컬렉션 형태를 1 : N 테이블을 생성해준다.
      @ElementCollection(fetch = FetchType.LAZY)
      // ⭐️ Enum명 그대로 저장 - 미사용 시 숫자로 저장됨
      @Enumerated(EnumType.STRING)
      @Builder.Default
      @Column(nullable = false)
      private Set<Roles> roles = new HashSet<>();
    }    
    ```
    
- ### 회원가입
- `PasswordEncoder` 설정
  - 미사용 시 Spring Security 내에서 비밀번호를 인가 해주지 않는다.
  - `@Bean`등록 필수
    - `SecurityConfig` 내부에서 PasswordEncoder의 내용을 변경 하고 Bean 등록 시 Cycle 에러가 발생하니 주의해주자.
      ```text
      The dependencies of some of the beans in the application context form a cycle:
       
      securityConfig defined in file [/Users/yoo/Desktop/Project/securityStudy/build/classes/java/main/com/yoo/securityStudy/config/SecurityConfig.class]
      ┌─────┐
      |  memberServiceImpl defined in file [/Users/yoo/Desktop/Project/securityStudy/build/classes/java/main/com/yoo/securityStudy/service/MemberServiceImpl.class]
      └─────┘
      ```
  - 사용 코드
  ```java
  // Bean Scan 대상 지정
  @Component
  public class AppConfig {
    // 👉 Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
  } 
  ```
- 비즈니스 로직
  - 사용 코드
  ```java
  @Service
  @RequiredArgsConstructor
  @Log4j2
  public class MemberServiceImpl implements MemberService, UserDetailsService {
      private final MemberRepository memberRepository;
      // 👉 의존성 주입
      private final PasswordEncoder passwordEncoder;
      @Override
      public SignUpRes registerMember(SignUpReq signUpReq) {
          // 👉 passwordEncoder.encode() 메서드를 통해 비밀번호 암호화
          signUpReq.setPassword(passwordEncoder.encode(signUpReq.getPassword()));
          Member member = memberRepository.save(this.dtoToEntity(signUpReq));
          return this.entityToSignUpRes(member);
      }
  }
  ``` 

- ### 인증
- `UserDetailsService`를 구한현 Class 와 메서드의 반환 타입인 User를 구현한 Class만 있으면 된다.
  - `UserDetailsService`
    - 필수로 `UserDetails loadUserByUsername(String username)`를 구현해야한다.
      - 해당 매서드가 인증을 담당한다
      - 반환 형식은 User Class 형식이다.
  - `User`
    - 인증이 완료되면 반환 되어야하는 형식이다.
    - 그대로 `new User()`를 통해 반환을 해도 괜찮다.
      - 다만 확정성을 위해 더욱 많은 정보를 넣고 싶다면 상속을 해줘야하기에 확장한 Class를 구현해야 한다.
    - 인증이 완료되면 `(Authentication authentication)`내 `authentication.getPrincipal()` 함수를 통해 확장한 Class의 객체에 접근이 가능하다.
- `UserDetailsService` 구현 Class
  ```java
  public interface MemberService {
  
    // 👉 User Class 권한 형식에 맞게 변환
    default Collection<? extends GrantedAuthority> authorities(Set<Roles> roles){
      return roles.stream()
              // ⭐️ "ROLE_" 접두사를 사용하는 이유는  Spring Security가 권한을 인식하고 처리할 때 해당 권한이 역할임을 명확하게 나타내기 위한 관례입니다.
              .map(r -> new SimpleGrantedAuthority("ROLE_"+r.name()))
              .collect(Collectors.toSet());
    }
  
    /**
     * Entity -> User DTO
     *
     * @param member the member
     * @return the member to user dto
     */
    default MemberToUserDTO entityToUserDto(Member member){
      return new MemberToUserDTO(member.getId()
              , member.getPassword()
              , member.getName()
              // 👉 권한 형식에 맞게 변경
              , this.authorities(member.getRoles())
              ,  member.getRoles());
    }
  
  }
  
  /////////////////////////////////////////////////////////////////////////////
  
  @Service
  @RequiredArgsConstructor
  @Log4j2
  public class MemberServiceImpl implements MemberService, UserDetailsService {
      private final MemberRepository memberRepository;
      
      @Transactional
      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          log.info("-----------------");
          log.info("Service 접근 - loadUserByUsername");
          log.info("-----------------");
  
          // 1. userName(아이디)를 기준으로 데이터 존재 확인
          Member member = memberRepository.findById(username)
                  .orElseThrow(()->new UsernameNotFoundException(username));
  
          // 2. 존재한다면 해당 데이터를 기준으로 User객체를 생성 반환
          //    🫵 중요 포인트는 해당 객체를 받아온 후 이후에 password 검증을 진행한다는 것이다
          return this.entityToUserDto(member);
      }
  }
  ```

- `User` 상속 Class
  ```java
  /**
   * extends User 를 사용하는 이유는 간단하다
   * UserDetails를 반환하는 loadUserByUsername()메서드에서
   * - 아이디, 비밀번호, 권한 << 이렇게 3개만 있으면 User를 사용해도 되지만
   *
   * 그렇지 않을 경우 추가적은 정보를 갖는 경우 아래와 같이 DTO를 추가후 Super()를 통해
   * 부모에게 필요한 생성정보를 전달 하고 나머지는 내가 필요한 정보를 들고 있기 위함이다.
   * */
  @Getter
  @Setter
  @ToString
  public class MemberToUserDTO extends User {
      private String id;
      private String password;
      private String name;
      private Set<Roles> roles;
  
      public MemberToUserDTO(String id
              , String password
              , String name
              , Collection<? extends GrantedAuthority> authorities
              , Set<Roles> roles
              ) {
          super(id, password, authorities);
          this.id = id;
          this.password = password;
          this.name = name;
          this.roles = roles;
      }
  }
  ```

## TODO List



- DB 계정 관리
  - 권한별 접근
- 커스텀 핸들러 적용
- jwt
  - Refresh token
