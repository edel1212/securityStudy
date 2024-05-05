# Spring Security Study

- 의존성을 추가하는 순간부터 모든 요청은 Scurity의 Filter를 거치게 된다.
  - 따라서 모든 요청은 Security에서 기본적으로 제공되는 LoginForm으로 이동된다.
    - 계정 및 비밀번호는 로그에 써 있다.

- Dependencies
```groovy
dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-security'
	testImplementation 'org.springframework.security:spring-security-test'
}
```

## 기본 Security 설정

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

## 예외 핸들러 설정

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

## `AuthFailureHandler`를 사용하지 않고 계정 및 비밀번호 예외 처리 방법
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

## UserDetailService 설정
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

## JWT

- Dependencies
```groovy
dependencies {
	//Jwt
	implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
	implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
	implementation 'io.jsonwebtoken:jjwt-jackson:0.11.5'
}
```

- Setting
```properties
# application.yml
############################
##Jwt Setting
############################
jwt:    
    # Token 만료 시간 - 다양한 방식으로 커스텀 가능하다 날짜 기준으로 계산 하려면 날짜로 하고 비즈니스로직에서 계산 등등
    # Ex)  {expirationDays} * 24 * 60 * 60;
    expiration_time: 60000
    # 사용할 암호 - 알려지면 안되니 실제 사용 시에는 암호화해서 넣어주자 
    secret: VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHa
```


- ### Jwt Business Logic
- `@Value("${jwt.expiration_time}")`를 통해 properties의 값을 읽어 사용한다.
- `@Component`를 통해 Bean 스캔 대상임을 지정해준다.
- 토큰 생성 시 파라미터를 `(Authentication authentication)`로 받는 이유는 확정성 떄문이다.
  - userDetailServer를 잘 구현했다면 커스텀한 인증 정보가 다 들어있기 때문이다. 
```java
public class JwtToken {
  // Jwt 인증 타입 [ Bearer 사용 ]
  private String grantType;
  // 발급 토근
  private String accessToken;
  // 리프레쉬 토큰
  private String refreshToken;
}

/////////////////////////////////////////////////////////////////////////////

@Log4j2
@Component
public class JwtUtil {
    @Value("${jwt.expiration_time}")
    private Long accessTokenExpTime;
    @Value("${jwt.secret}")
    private String secret;

    /**
     * createAccessToken 이슈로 인해 재생성 중
     *
     * - 👉 Authentication을 통해 로그인한 정보를 받아서 사용이 가능하다!!
     * */
    public JwtToken generateToken(Authentication authentication){

        // 로그인에 성공한 사용자의 권한을 가져온 후 문자열로 반환
        // ex) "ROLE_USER,ROLE_MANAGER,ROLE_ADMIN"
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        // 로그인에 성공한 계정Id
        String userName = authentication.getName();

        // 토큰 만료시간 생성
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime tokenValidity = now.plusSeconds(this.accessTokenExpTime);

        Claims claims = Jwts.claims();
        claims.put("memberId", userName);
        claims.put("auth", authorities);

        // Jwt AccessToken 생성
        String accessToken =  Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(tokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        // Refresh Token 생성
        // 토큰 만료시간 생성
        ZonedDateTime reNow = ZonedDateTime.now();
        ZonedDateTime reTokenValidity = reNow.plusSeconds(this.accessTokenExpTime);
        String refreshToken = Jwts.builder()
                .setExpiration(Date.from(reTokenValidity.toInstant()))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * JWT 검증
     * - 각각 예외에 따라 ControllerAdvice를 사용해서 처리가 가능함
     * @param accessToken
     * @return IsValidate
     */
    public boolean validateToken(String accessToken) {
        try {
            Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(accessToken);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        } // try - catch
        return false;
    }

    /**
     * JWT Claims 추출
     * @param accessToken
     * @return JWT Claims
     */
    public Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }// try - catch
    }

}
```

- ### Jwt 인증 흐름
- 로그인 요청이 들어온다.
  - 해당 요청 Url Path는 인증을 거치지 않게 Security Config에서 설정 `web -> web.ignoring().requestMatchers(HttpMethod.POST,"/member/login")`
  - 의존성 주입된 `AuthenticationManagerBuilder`의 `.getObject().authenticate(UsernamePasswordAuthenticationToke)` 로직 이동
      ```java
      @RequestMapping(value = "/member", produces = MediaType.APPLICATION_JSON_VALUE)
      @RequiredArgsConstructor
      @RestController
      @Log4j2
      public class MemberController {
    
        private final AuthenticationManagerBuilder authenticationManagerBuilder;
        private final JwtUtil jwtUtil;
    
        @PostMapping("/login")
        public ResponseEntity login(@RequestBody LoginDTO loginDTO){
          log.info("------------------");
          log.info("Login Controller 접근");
          log.info("------------------");
          // 1. username + password 를 기반으로 Authentication 객체 생성
          // 이때 authentication 은 인증 여부를 확인하는 authenticated 값이 false
          UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getId()
                  , loginDTO.getPassword());
    
          /** 실제 검증 후 반환하는  authentication에는 내가 커스텀한 UserDetail정보가 들어가 있음*/
          // 2. 실제 검증. authenticate() 메서드를 통해 요청된 Member 에 대한 검증 진행
          // authenticate 메서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드 실행
          Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
    
          JwtToken token = jwtUtil.generateToken(authentication);
    
          return ResponseEntity.ok().body(token);
        }
    
      }
      ```
- 작성했던 `UserDetailServer`의 `loadUserByUsername(String username)` 메서드를 사용하여 User 객체 생성
- 인증이 완료되었다면 `jwtUtil`을 사용하여 토큰 생성


## Jwt 인증 절차

- 기존 Security Filter에서 순서를 변경해줘야한다.
- `@Component`를 통해 Bean 스캔 대상임을 지정해준다.
- `OncePerRequestFilter`를 상속한 Class에서 처리한다.
  - 구현이 강제 되어있는 `doFilterInternal()`메서드에서 로직을 구현해준다.
    - 내부에서 받아오는 `HttpServletRequest request`에서 Header에 포함되어있는 토큰값을 검증한다.
  - 값에 이상이 없을 경우 ` SecurityContextHolder.getContext().setAuthentication(authentication);`를 통해 권한을 등록해준다.
    - 이때 넘어어온 권한 목록(`authentication`)는 `ROLE_`형식의 prefix가 붙어있다.
- 흐름
  - `JwtUtil` 추가로직
    - `"Bearer "`을 제거한 JWT 값 추출
      ```java
      @Log4j2
      @Component
      public class JwtUtil {
          /**
           * JWT 값 추출
           * @param request
           * @return String Jwt Token 원문 값
           */
          public String resolveToken(HttpServletRequest request) {
              String bearerToken = request.getHeader(AUTHORIZATION);
              if (bearerToken == null || !bearerToken.startsWith("Bearer ")) return null;
              return bearerToken.replaceAll("Bearer ", "");
          }
      }  
      ```
      - 토큰 값을 통해 Authentication 객체 생성
        - ℹ️ 권한 정보는 `ROLE_ADMIN, ROLE_USER`형식으로 prefix가 붙어있다.
          - 로그인 시 Security 자체 메서드에서 받아왔기 때문이다.
            ```java
            @RequestMapping(value = "/member", produces = MediaType.APPLICATION_JSON_VALUE)
            @RequiredArgsConstructor
            @RestController
            @Log4j2
            public class MemberController {
          
                private final AuthenticationManagerBuilder authenticationManagerBuilder;
                private final JwtUtil jwtUtil;
          
                @PostMapping("/login")
                public ResponseEntity login(@RequestBody LoginDTO loginDTO){
                    log.info("------------------");
                    log.info("Login Controller 접근");
                    log.info("------------------");
                    // 1. username + password 를 기반으로 Authentication 객체 생성
                    // 이때 authentication 은 인증 여부를 확인하는 authenticated 값이 false
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getId()
                            , loginDTO.getPassword());
          
                    /** 실제 검증 후 반환하는  authentication에는 내가 커스텀한 UserDetail정보가 들어가 있음*/
                    // 2. 실제 검증. authenticate() 메서드를 통해 요청된 Member 에 대한 검증 진행
                    // authenticate 메서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드 실행
                    Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
          
                    JwtToken token = jwtUtil.generateToken(authentication);
          
                   return ResponseEntity.ok().body(token);
                }
          
            }
            ```
          - `Authentication` 객체 생성
            ```java
            @Log4j2
            @Component
            public class JwtUtil {
                /**
               * 토큰 값을 통해 Authentication 객체 생성
               *
               * @param accessToken the access token
               * @return the authentication
               */
              public Authentication getAuthentication(String accessToken) {
                  // 1 . 토큰에서 Claims 값을 가져온다. - 내가 넣은 값이 들어있음
                  Claims claims = this.parseClaims(accessToken);

                  // 2 . 주입된 토큰에서 내가 넣은 값의 유무를 체크
                  if(claims.get("memberId") == null || claims.get("auth") == null) {
                      // 예외 발생 시켜 처리하자
                      throw new RuntimeException();
                  }// if

                  // 3 . claims에서 권한 정보 추출 후 Spring Security의 권한 형식에 맞게 변환
                  //   ⭐️ jwt에 등록된 권한은 Security자체에서 주입된 값이기에 ROLE_가 prefix로 붙어있다!
                  //      ex) ROLE_ADMIN, ROLE_USER
                  Collection<? extends GrantedAuthority> authorities =
                          Arrays.stream(claims.get("auth").toString().split(","))
                                  .map(SimpleGrantedAuthority::new)
                                  .collect(Collectors.toList());
                  // 계정ID
                  String username = claims.get("memberId").toString();

                  // 4 . UserDetail 객체 생성
                  UserDetails principal = new User(username, "", authorities);

                  // UsernamePasswordAuthenticationToken로 반환 - uerDetail 정보와 권한 추가
                  return new UsernamePasswordAuthenticationToken(principal, "", authorities);
              }
            }  
            ```
  - `OncePerRequestFilter`을 상속한 Class
    - 한 요청에 대해 한번만 실행하는 필터이다. 포워딩이 발생하면 필터 체인이 다시 동작되는데, 인증은 여러번 처리가 불필요하기에 한번만 처리를 할 수 있도록 도와주는 역할을 한다.
    - 의존성 주입 후 `http.addFilterBefore()`메서드를 통해 `UsernamePasswordAuthenticationFilter` 필터 실행 전에 실행하도록 변경
      ```java
      @Configuration
      @RequiredArgsConstructor
      @Log4j2
      public class SecurityConfig {
            // Jwt 필터 추가
          private  final JwtFilter jwtFilter;
          @Bean
          public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
             // 👉 필터 순서 번경
              http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
              return http.build();
          }
      }
      ```

## 권한별 접근제어
- Security 내부 권한 확인 시 `"ROLE_"`로 앞에 prefix가 붙는다.
- Jwt와 같은 Spring Security 내부에서 Session을 사용하지 않을 경우 권한 정보를 `Security Context` 내부에 따로 주입이 필요하다.
- 접근 제어를 지정해 줄 경우 순서가 중요하다.
  - `anyRequest().authenticated();`의 경우 모든 요청이 권한 체크가 필요하다인데 가장 위에 적용할 경우 컴파일 에러 발생
- 접근 제어 설정
  - `authorizeHttpRequests()` 사용 방법
    - 직관적으로 URL 및 HttpMethod를 지정할 수 있다.
    - URL PATH가 바뀔 경우 번거롭게 한번 더 수정이 필요하다.
    - 제어해야할 Path가 많아질 경우 관리가 힘들어진다.
    - 설정 코드
      ```java
      @Configuration
      @RequiredArgsConstructor
      @Log4j2
      public class SecurityConfig {
          @Bean
          public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
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
              return http.build();
          }
      }
      ```
- `@EnableMethodSecurity`를 사용한 방식
  - Method 상단 권한 체크 메서드를 통해서 접근을 제어할 수 있다.
  - `@PreAuthorize` 내에서 사용가능한 함수/기능들
  
    | 함수/기능             | 설명                                                                                         |
    |----------------------|----------------------------------------------------------------------------------------------|
    | hasRole([role])      | 현재 사용자의 권한이 파라미터의 권한과 동일한 경우 true                                      |
    | hasAnyRole([role1, role2, ...]) | 현재 사용자의 권한이 파라미터의 권한 중 하나와 일치하는 경우 true                           |
    | principal            | 사용자를 증명하는 주요 객체(User)에 직접 접근 가능                                           |
    | authentication       | SecurityContext에 있는 authentication 객체에 접근 가능                                      |
    | permitAll            | 모든 접근을 허용                                                                            |
    | denyAll              | 모든 접근을 거부                                                                            |
    | isAnonymous()        | 현재 사용자가 익명(비로그인) 상태인 경우 true                                                |
    | isRememberMe()       | 현재 사용자가 RememberMe 사용자인 경우 true                                                  |
    | isAuthenticated()    | 현재 사용자가 익명이 아니고 (로그인 상태인 경우) true                                         |
    | isFullyAuthenticated() | 현재 사용자가 익명이 아니고 RememberMe 사용자가 아닌 경우 true                                 |
  - 예시

```java
@RestController
public class AccessController {

  @GetMapping("/all")
  @PreAuthorize("permitAll()")  // 👍 권한이 있는 모두가 접근 가능
  public ResponseEntity allAccess(){
    return ResponseEntity.ok("All - Member Access!!");
  }

  @GetMapping("/user")
  public ResponseEntity userAccess(){
    return ResponseEntity.ok("User Access!!");
  }

  @GetMapping("/manager")
  // 👍 다양한 조건문을 사용 가능하다.
  // @PreAuthorize("isAuthenticated() and (( returnObject.name == principal.name ) or hasRole('ROLE_ADMIN'))")
  @PreAuthorize("hasRole('ROLE_MANAGER')")
  public ResponseEntity managerAccess(Authentication authentication){
    log.info("-----------------------------");
    authentication.getAuthorities().stream().forEach(log::info);
    log.info("-----------------------------");
    return ResponseEntity.ok("manager Access!!");
  }

  @GetMapping("/admin")
  @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
  public ResponseEntity adminAccess(Authentication authentication){
    log.info("-----------------------------");
    authentication.getAuthorities().stream().forEach(log::info);
    log.info("-----------------------------");
    return ResponseEntity.ok("admin Access!!");
  }
}
```


## TODO List






- 권한별 접근
- jwt
  - Refresh token
- 소셜 로그인
  - Google
  - Kakao
  - Naver
