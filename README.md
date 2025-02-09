# Spring Security Study

```properties
# ✅ 의존성을 추가하는 순간부터 모든 요청은 Security의 Filter를 거치게 된다.
#    - 추가적인 설정이 없을 경우 spring security에서 기본적으로 제공되는 LoginForm으로 이동
##     - 계정 및 비밀번호는 console log에 작성 되어있음  
```

## 1 ) 기본 설정 방법

### 1 - 1 ) build.gradle

```groovy
dependencies {
	implementation 'org.springframework.boot:spring-boot-starter-security'
	testImplementation 'org.springframework.security:spring-security-test'
}
```
### 1 - 2 ) Security Config Class 설정

- SpringBoot 버전이 올라가면서 Security 설정 방법이 **변경 됨**
  - Security6
    - 모든 옵션 적용 방법이 **체이닝 -> 함수형**으로 변경
- 설정 class이므로 `@Configuration`를 지정 하여 Bean에 등록
- `SecurityFilterChain`을 반환하는 Medthod 생성 후 `@Bean` 등록
  - 초기 메서드 생성 후 **모든 요청 접근 허용**으로 변경
- `SecurityFilterChain` 반환 메서드의 `HttpSecurity`에 옵션을 추가하는 방식
- FunctionalInterface 인 `WebSecurityCustomizer`에서 security filter에서 **검증을 제외할 요청을 지정**할 수 있다
  - 정적 파일을 사용할 경우 지정 필수

  ```java
  @Configuration
  @Log4j2
  public class SecurityConfig {

      @Bean  
      public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
          // 👉 CSRF 사용 ❌
          http.csrf(csrf -> csrf.disable());
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

## 2 ) CORS 설정 방법
- CorsConfigurationSource 반환 Method에 설정 내용 구현 후 `SecurityFilterChain` 내 `http.cors()`에 주입
  - Bean 등록 필수
```java
@Component
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // ℹ️ CORS 설정
        http.cors(cors->{
            cors.configurationSource(corsConfigurationSource());
        });

        return http.build();
    }

    /**
     * <h3>CORS 설정</h3>
     *
     * @return the cors configuration source
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // 새로운 CORS 설정 객체 생성
        CorsConfiguration configuration = new CorsConfiguration();
        // 모든 출처에서의 요청을 허용
        configuration.addAllowedOriginPattern("*");
        // 모든 HTTP 메소드를 허용 (GET, POST, PUT, DELETE, OPTIONS 등)
        configuration.setAllowedMethods(Collections.singletonList("*"));
        // 모든 HTTP 헤더를 허용
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        // 자격 증명(예: 쿠키, 인증 정보)을 포함한 요청을 허용
        configuration.setAllowCredentials(true);
        // 캐시 시간을 3600초(1시간)으로 설정
        configuration.setMaxAge(3600L);

        // URL 경로에 기반한 CORS 설정 소스 객체 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 경로에 대해 위에서 설정한 CORS 구성을 등록
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```


## 3 ) Custom 예외 Handler

### 3 - 1 ) `AuthenticationEntryPoint` 설정
```properties
# ✅ Spring Security에서 인증되지 않은 사용자가 보호된 리소스에 접근할 때 호출되는 진입점(Entry Point)을 제어  
#    -  **인증이 필요한데, 인증되지 않은 사용자가 접근했을 때** 를 제어
```

#### 3 - 1 - A ) Custom AuthenticationEntryPoint Class 
- `AuthenticationEntryPoint`의 void 형태인 `commence()`를 구현
- `@Component`를 사용하여 Bean 등록
```java
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
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

#### 3 - 1 - B ) SecurityConfig
- `exceptionHandling()`내 해당 custom handler 주입
```java
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    // Custom Exception Handling
    http.exceptionHandling(handling ->
            handling
                    // ✨ AuthenticationEntryPoint
                    .authenticationEntryPoint(customAuthenticationEntryPoint)
    );
    return http.build();
  }
}
```


### 3 - 2 ) `AccessDeniedHandler` 설정
- 사용자가 인증은 되었지만, 해당 리소스를 접근할 권한이 없을 때 어떻게 응답할지를 지정

#### 3 - 2 - A ) Custom CustomAccessDeniedHandler Class
- `AccessDeniedHandler`의 void 형태인 `handle()`를 구현
- `@Component`를 사용하여 Bean 등록 

```java
@Log4j2
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
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

#### 3 - 2 - B ) SecurityConfig
- `exceptionHandling()`내 해당 custom handler 주입
```java
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

  private final CustomAccessDeniedHandler customAccessDeniedHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    // Custom Exception Handling
    http.exceptionHandling(handling ->
            handling
                    // ✨ AccessDeniedHandler
                    .authenticationEntryPoint(customAccessDeniedHandler)
    );
    return http.build();
  }
}
```

### 3 - 3 ) `AuthFailureHandler` 설정
- **폼 로그인 (formLogin())이나 UsernamePasswordAuthenticationFilter**를 사용할 때 인증 실패를 처리하기 위해 사용
  - 세션 기반 인증에서는 로그인 요청을 POST /login으로 보내고, 서버에서 인증 실패 시 failureHandler를 실행 
  -  **jwt 를사용할 경우 사용이 불가능하다._**

#### 3 - 3 - A ) Custom SimpleUrlAuthenticationFailureHandler Class
- `SimpleUrlAuthenticationFailureHandler`를 상속하여 `onAuthenticationFailure()`를 **Override 하여 진행**
  - Interface인 `AuthenticationFailureHandler`를 구현하여 진행 또한 가능 
  - `SimpleUrlAuthenticationFailureHandler`를 사용 이유는?
    - `AuthenticationFailureHandler`를 구한현 클래스이므로 같은 기능을 작동한다.
- `@Component`를 지정하여 Bean 등록 필요
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
#### 3 - 3 - B ) SecurityConfig

- `formLogin()`내 함수 등록 `failureHandler(customAuthFailureHandler)`
- ℹ️ 중요 확인 사항
  - `loginProcessingUrl()`에 등록된 주소는 Controller가 없다 action="주소"에 해당되는 값이다.
    - Spring Security의 필터에서 제외 되기에 FailureHandler를 등록해도 제외된다.
    - ✨ `formLogin()`에서 `loginProcessingUrl()`를 지정하면 **누구나 접근이 가능** 
```java
@Configuration
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
  private final CustomAuthFailureHandler customAuthFailureHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    // 👉 로그인을 사용할 loginProcessingUrl을  Front단 action 주소임 - 컨트롤러 없음 설정해준다.
    http.formLogin(login->login.loginProcessingUrl("/member/login")
            .failureHandler(customAuthFailureHandler));
    return http.build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer(){
      return web -> web.ignoring()
              /*********************************************/
              /** 아래 주석 내용떄문에 삽질함 ... */
              /*********************************************/
              // Login 접근 허용
              //.requestMatchers(HttpMethod.POST,"/member/login"))
              ;  
  }
}
```

### 3 - 4 ) 계정 및 비밀번호 예외 처리 방법 - `AuthFailureHandler` 사용 ❌   

```properties
# ✅ 방법은 크게 2가지가 존재함 
#    - 1 ) `UsernamePasswordAuthenticationFilter`를 상속한 클래스를 만든 후 Filter 순서를 바꾸는 방법
#    - 2 ) `@RestControllerAdvice`를 지정한 ExceptionController를 구현하여 처리하는 방법    
```

#### ✨ `UsernamePasswordAuthenticationFilter` 방법
- Spring Security의 필터의 순서를 바꿔서 진행하는 방법
- Security의 사용 방법에서 크게 벗어나지 않지는 방법
- **로그인 시** 파라미터를 받는 방식에 대한 **추가 설정 필요**함
  - form 방식 일 경우
    - `HttpServletRequest`에서 `request.getParameter("아이디 또는 비밀번호")`를 사용
  - json 방식일 경우
    - `RequestLogin requestLogin = mapper.readValue(request.getInputStream(), RequestLogin.class);`


#### 3 - 4 - A ) Custom UsernamePasswordAuthenticationFilter Class 설정
```properties
# ✅ UsernamePasswordAuthenticationFilter는 AbstractAuthenticationProcessingFilter를 상속은 class 이다.
#
# ✏️ 중요
#  - **Bean 등록 대상이 아닌** 객체 생성을 통해 주입되는 Class 이므로 `@Component` 어노테이션은 필요 없다.
#  - 부모 **생성자 메서드의 인자 값은 필수**이다. 없을 경우 null point exception 발생
#    - `super(authenticationManager);`에 필요 값은 **AuthenticationManager** 이다.
#    - ✍️ @RequiredArgsConstructor를 사용해도 부모 생성 메서드인 super()에는 주입되지 않으니 주의하다!
```
- 필요한 메서드들을 `@Override` 하여 구현 필요
  - 로그인  : `Authentication attemptAuthentication()`
    - 반환 값은 `getAuthenticationManager()`를 사용해 new UsernamePasswordAuthenticationToken()를 주입 해주자
      - username, password, roles 순서이며, **roles의 경우 optional이다.**
  - 성공   : `void successfulAuthentication()`
  - 실패   : `void unsuccessfulAuthentication()`

```java
@Log4j2
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  public AuthenticationFilter(AuthenticationManager authenticationManager) { super(authenticationManager); }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    try {
      var mapper = new ObjectMapper();
      RequestLogin requestLogin = mapper.readValue(request.getInputStream(), RequestLogin.class);
      log.info("getEmail ::: {}", requestLogin.getEmail());
      log.info("getPassword ::: {}", requestLogin.getPwd());
      return getAuthenticationManager().authenticate(
              new UsernamePasswordAuthenticationToken(requestLogin.getEmail(), requestLogin.getPwd(), new ArrayList<>()));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

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
    super.unsuccessfulAuthentication(request, response, failed);
  }
  
}
```

#### 3 - 4 - B ) Security Config
- UserDetailService 부분은 제외하여 진행
```java
@Configuration
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // SecurityFilterChain 내에서 AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        // UserDetailsService(사용자 정보 조회 서비스) 및 비밀번호 인코딩 방식 지정
        authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder);
        // AuthenticationManager 객체 생성 (Spring Security에서 인증을 담당하는 핵심 객체)
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
        // Spring Security의 인증 매니저로 설정
        http.authenticationManager(authenticationManager); 
        
        // 필터 등록
        http.addFilter(this.getAuthenticationFilter(authenticationManager));
        return http.build();
    }

    private AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager){
        return new AuthenticationFilter(authenticationManager);
    }
}
```

#### 3 - 4 - C ) Password Config
```java
@Configuration
public class PasswordConfig {
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```


#### ✨ `@RestControllerAdvice` 방법
- 간단하게 발생하는 예외를 Catch하여 반환하는 방법
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
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
}
```

## 4 ) UserDetailService 설정

- **DB를** 통해 회원을 관리하기 위해서는 꼭 필요한 설정이다.
- `UserDetailsService`를 구현한 구현체 클래스가 필요하다.
  - Interface에서 구현을 강제하는 메서드 `UserDetails loadUserByUsername()`를 통해 인증을 진행
    - 반환 값은 User를 반환 또는 상속한 Class를 반환 필요
      - `User`를 반환해도 괜찮지만 아이디, 패스워드, 권한 밖에 없으므로 상속을 통해 다양한 데이터를 객체로 커스텀이 가능하기에 상속을 통해 처리

### 4 - 1 ) Entity

### 4 - 1 - A ) 권한
- Enum을 통해 Table을 생성
```java
public enum Roles {
  USER ,
  MANAGER ,
  ADMIN ,
}
```
### 4 - 1 - A ) 회원 Entity
- 권한 설정의 경우 enmu에 대해 `@Enumerated(EnumType.STRING)`를 통해 Enum이 숫자가 아닌 문자형태로 지정한 권한이 저장 및 `@ElementCollection(fetch = FetchType.LAZY)`을 통해 해당 테이블은 `회원ID, 권한`이 PK로 설정 됨 
```java
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
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

### 4 - 2  ) PasswordEncoder 설정
- `SecurityConfig` 내부에서 PasswordEncoder를 Bean 등록 시 **Cycle (순환 참조) 에러**가 발생하니 주의하자
  ```text
  The dependencies of some of the beans in the application context form a cycle:

  securityConfig defined in file [/Users/yoo/Desktop/Project/securityStudy/build/classes/java/main/com/yoo/securityStudy/config/SecurityConfig.class]
  ┌─────┐
  |  memberServiceImpl defined in file [/Users/yoo/Desktop/Project/securityStudy/build/classes/java/main/com/yoo/securityStudy/service/MemberServiceImpl.class]
  └─────┘
  ```
- 미사용 시 Spring Security 내에서 비밀번호를 인가 해주지 않음 필수 사항
- `@Bean`등록 필수 사항

```java
@Configuration
public class PasswordConfig {
  @Bean
  public PasswordEncoder passwordEncoder(){
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
```

### 4 - 3  ) 회원 등록
- PasswordEncoder를 사용해 **비밀번호를 encoding 후 저장** 필수 
```java
@Service
@RequiredArgsConstructor
@Log4j2
public class MemberServiceImpl implements MemberService, UserDetailsService {
    private final MemberRepository memberRepository;
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

### 4 - 4  ) 인증 Logic
- Interface인 `UserDetailsService`를 구한현 Class 와 `UserDetails loadUserByUsername(String username)`를 **구현** 해주면 된다.
  - 해당 매서드는 인증을 담당하며, implements 시 구현은 필수 이다.
  - return 시  User class를 반환해도 괜찮다.

#### 4 - 4 - A  ) UserDetailService
- Servcie class에 UserDetailsService를 **상속하여 진행**
```java
public interface MemberService extends UserDetailsService {
    
  default MemberToUserDTO entityToUserDto(Member member){
    return new MemberToUserDTO(member.getId()
            , member.getPassword()
            , member.getName()
            // 👉 권한 형식에 맞게 변경
            , this.authorities(member.getRoles())
            ,  member.getRoles());
  }
  
  // 👉 User Class 권한 형식에 맞게 변환
  default Collection<? extends GrantedAuthority> authorities(Set<Roles> roles){
    return roles.stream()
            // ⭐️ "ROLE_" 접두사를 사용하는 이유는  Spring Security가 권한을 인식하고 처리할 때 해당 권한이 역할임을 명확하게 나타내기 위한 관례입니다.
            .map(r -> new SimpleGrantedAuthority("ROLE_"+r.name()))
            .collect(Collectors.toSet());
  }
}
```

#### 4 - 4 - B  ) UserDetailServiceImpl
```java
@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService, UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. userName(아이디)를 기준으로 데이터 존재 확인
        Member member = memberRepository.findById(username)
                .orElseThrow(()->new UsernameNotFoundException(username));
        // 2. 존재한다면 해당 데이터를 기준으로 User객체를 생성 반환
        //    🫵 중요 포인트는 해당 객체를 받아온 후 이후에 password 검증을 진행한다는 것이다
        return this.entityToUserDto(member);
    }
}
```

#### 4 - 4 - C  ) UserDetails
```properties
# ✅ 참고 : public class User implements UserDetails, CredentialsContainer { /** code */ }
```
- `UserDetailsService` 구현 Class이다.
- 인증이 완료되면 반환 해야하는 객체이며, `new User()`를 통해 반환을 해도 괜찮도 상관은 없다. 
  - 다만 보편적으로 **확정성을 위해** 더욱 많은 정보를 넣고 상속 후 확장한 Class를 통해 구현
  - 인증이 완료 후 `(Authentication authentication)` -> `authentication.getPrincipal()`를 통해 확장한 Class의 객체에 접근이 가능
```java
/**
 * extends User 를 사용하는 이유는 간단하다
 * UserDetails를 반환하는 loadUserByUsername()메서드에서
 * - 아이디, 비밀번호, 권한 << 이렇게 3개만 있으면 User를 사용해도 되지만
 *
 * 그렇지 않을 경우 추가적은 정보를 갖는 경우 아래와 같이 DTO를 추가후 Super()를 통해
 * 부모에게 필요한 생성정보를 전달 하고 나머지는 내가 필요한 정보를 들고 있기 위함이다.
 * */
@Data
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

### 4 - 5  ) Security Config 
```properties
# UsernamePasswordAuthenticationFilter를 사용할 경우는 위에 작성 되어 있으니 다른 방법을 사용하여 userDetailService를 주입
```
- 간단하게 userDetailService를 지정하여 사용 가능
```java
@Configuration
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final Environment env;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        
        http.userDetailsService(userService);
        
        return http.build();
    }

}
```


## 5 ) JWT

### 5 - 1 )  build.gradle
- api, impl, jackson 3개 모두가 필요하다. 서로가 서로를 사용하는 개념임
```groovy
dependencies {
    // Jwt https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api
    implementation group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.12.6'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.12.6'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.12.6'
}
```

### 5 - 2 )  application.yml

```properties
jwt:
    # Token 만료 시간 - 다양한 방식으로 커스텀 가능하다 날짜 기준으로 계산 하려면 날짜로 하고 비즈니스로직에서 계산 등등
    # Ex)  {expirationDays} * 60(초) * 60(분) * 24(시간) * 1000;  [ 하루 ]
    expiration_time: 86400000
    # 사용할 암호 - 알려지면 안되니 실제 사용 시에는 암호화해서 넣어주자
    secret: VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHa
```

### 5 - 3 )  Jwt Token 생성
- 로그인 성공 방식에 따른 방법을 2가지로 나눠서 설명 함 [ successfulAuthentication() 사용 시, Controller를 통해 로그인 시  ]

### 5 - 3 - A )  successfulAuthentication() 사용 시

#### ℹ️ Security Config
- 상단의 UsernamePasswordAuthenticationFilter 설정과 차이점은  UserService 와 Environment를 주입 받아 사용한 다는 점이다.
```java
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
  private final PasswordEncoder passwordEncoder;
  private final UserService userService;
  private final Environment env;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
              AuthenticationManagerBuilder authenticationManagerBuilder =
              http.getSharedObject(AuthenticationManagerBuilder.class);
              authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(passwordEncoder);
              AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
              http.authenticationManager(authenticationManager);
              http.addFilter(this.getAuthenticationFilter(authenticationManager));
      return http.build();
    }

  private AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager){
      return new AuthenticationFilter(authenticationManager, userService, env);
    }
}

```
#### ℹ️ Custom UsernamePasswordAuthenticationFilter   
- Jwts를 사용하여 토큰을 생성하며 필요한 내용을 builder pattern 방식으로 주입하여 생성 가능
```java
@Log4j2
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final UserService userService;
    private final Environment env;

    public AuthenticationFilter(AuthenticationManager authenticationManager, UserService userService, Environment env) {
        super(authenticationManager);
        this.userService = userService;
        this.env = env;
    }
    
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String userName = ((User)authResult.getPrincipal()).getUsername();
        UserDto userDto = userService.getUserDetailsByEmail(userName);
        String userId = userDto.getUserId();
        // 만료 시간을 밀리초로 설정하여 Date 객체로 변환
        long expirationTime = Long.valueOf(env.getProperty("token.expiration-time"));
        Date expirationDate = new Date(System.currentTimeMillis() + expirationTime);
        // secretKey
        String secretKey    = env.getProperty("token.secret");
        byte[] keyBytes     = Decoders.BASE64.decode(secretKey);
        Key key             = Keys.hmacShaKeyFor(keyBytes);

        // token key 생성
        String token = Jwts.builder()
                // 사용자 또는 애플리케이션을 식별하는 값
                .subject(userId)
                // 만료 시간
                .expiration(expirationDate)
                // 알고리즘 방식
                .signWith(key)
                .compact();

        response.addHeader("token", token);
        response.addHeader("userId", userId);
    }
}
```

### 5 - 3 - B )  Controller을 사용한 로그인 시

#### ℹ️ 로그인
- 필수 적으로 해당 요청은 filter 인증에서 제외할 수 있도록 설정 해줘야햔다.
- 흐름
  - 1 . username + password 를 기반으로 authenticationToken 생성
  - 2 . authenticate() 메서드를 통해 요청된 Member 에 대한 검증 진행 - 실질적 검증 진행 ( 1에서 전달 받은 token 과 DB상 비밀번호 매칭 진행 )
    - authenticate 메서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드 실행
    - `UserDetailServer`의 `loadUserByUsername(String username)` 메서드를 사용하여 User 객체 생성
  - 3 . authentication 정보를 통해 Jwt Token 생성
```java
@RequestMapping(value = "/member", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@RestController
public class MemberController {

  private final AuthenticationManagerBuilder authenticationManagerBuilder;
  private final JwtUtil jwtUtil;

  @PostMapping("/login")
  public ResponseEntity login(@RequestBody LoginDTO loginDTO){
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

#### ℹ️ Jwt Token 생성
##### DTO
```java
public class JwtToken {
  // Jwt 인증 타입 [ Bearer 사용 ]
  private String grantType;
  // 발급 토근
  private String accessToken;
  // 리프레쉬 토큰
  private String refreshToken;
}
```

##### 생성
- `@Value("${jwt.expiration_time}")`를 통해 properties의 값을 읽어 사용
- `@Component`를 통해 Bean 스캔 대상임을 지정
- 토큰 생성 시 파라미터를 `(Authentication authentication)`를 지정하는 이유는 **userDetail 정보를 사용하기 위함**
```java
@Log4j2
@Component
public class JwtUtil {
    @Value("${jwt.expiration_time}")
    private Long accessTokenExpTime;
    @Value("${jwt.secret}")
    private String secretKey;

    public JwtToken generateToken(Authentication authentication){

        // 로그인에 성공한 사용자의 권한을 가져온 후 문자열로 반환
        // ex) "ROLE_USER,ROLE_MANAGER,ROLE_ADMIN"
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        // 로그인에 성공한 계정Id
        String userName = authentication.getName();

        // 만료 시간을 밀리초로 설정하여 Date 객체로 변환
        Date expirationDate = new Date(System.currentTimeMillis() + accessTokenExpTime);

        Claims claims = Jwts.claims();
        claims.put("memberId", userName);
        claims.put("auth", authorities);

        // secretKey       
        byte[] keyBytes     = Decoders.BASE64.decode(secretKey);
        Key key             = Keys.hmacShaKeyFor(keyBytes);
        
        // Jwt AccessToken 생성
        String accessToken =  Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(Date.from(Instant.now()))
                // 만료 시간
                .expiration(expirationDate)
                // 알고리즘 방식
                .signWith(key)
                .compact();

        // Refresh Token 생성
        // 토큰 만료시간 생성
        Date reTokenValidity = new Date(System.currentTimeMillis() + (accessTokenExpTime * 2 ));
        String refreshToken = Jwts.builder()
                .expiration(reTokenValidity)
                .signWith(key)
                .compact();

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
```

## 6 ) Jwt 인증 절차

### 6 - 1 ) OncePerRequestFilter 
- 요청에 대해 **한번만 실행하는 필터**이다. 포워딩이 발생하면 필터 체인이 다시 동작 되는데, **인증은 여러번 처리가 불필요하기에 한번만 처리를 할 수 있도록 도와주는 역할**을 험
- Jwt에 대한 기능을 구현한 class 의존성 주입 후 `http.addFilterBefore()`메서드를 통해 `UsernamePasswordAuthenticationFilter` 필터 실행 전에 실행하도록 변경
  - UsernamePasswordAuthenticationFilter 전에 **header 내 bearer token이 있을 경우** 해당 **토큰을 사용해서 인증**을 해버리는 것이다. 
```java
@Configuration
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
      // Jwt 필터 추가
    private final JwtFilter jwtFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
       // 👉 필터 순서 번경
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

### 6 - 2 ) Jwt 검증 로직
```java
@Log4j2
@Component
public class JwtUtil {
    @Value("${jwt.expiration_time}")
    private Long accessTokenExpTime;
    @Value("${jwt.secret}")
    private String secret;

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

    /**
     * JWT 값 추출
     * @param request
     * @return String Jwt Token 원문 값
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) return null;
        return bearerToken.replaceAll("Bearer ","");
    }


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

    /**
     * AccessToken 내 Bearer 제거
     *
     * @param AccessToken the access token
     * @return removeBearer
     */
    private String removeBearer(String AccessToken){
        return AccessToken.replaceAll("Bearer ","");
    }
}
```


## 7 ) 권한별 접근제어

- Security 내부 권한 확인 시 `"ROLE_"`로 앞에 prefix가 붙는다.
- Jwt와 같은 Spring Security 내부에서 Session을 사용하지 않을 경우 권한 정보를 `Security Context` 내부에 따로 주입이 필요하다.
- 접근 제어를 지정해 줄 경우 순서가 중요하다.
  - `anyRequest().authenticated();`의 경우 모든 요청이 권한 체크가 필요하다인데 가장 위에 적용할 경우 컴파일 에러 발생
- 접근 제어 설정 방법은 2개지가 있다 [ `authorizeHttpRequests()` 사용 방법, `@EnableMethodSecurity`를 사용 방법 ]

### 7 - 1 ) `authorizeHttpRequests()` 사용 방법 

- 직관적으로 URL 및 HttpMethod를 지정할 수 있다.
- URL PATH가 바뀔 경우 번거롭게 한번 더 수정이 필요하다.
- 제어해야할 Path가 많아질 경우 관리가 힘들어진다.

### 7 - 1 - A ) Security Config

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

## 7 - 2 ) `@EnableMethodSecurity`를 사용 방법

### 7 - 2 - A ) Security Config
- `@EnableMethodSecurity`를 사용하여 할성화 시킴
  - 기본적으로 prePostEnabled = true로 동작 → @PreAuthorize, @PostAuthorize 자동 활성화
  - @Secured, @RolesAllowed를 사용하려면 명시적으로 활성화해야 함
    - ex) `@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)`
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http.build();
    }
}
```

### 7 - 2 - B ) Controller
- Method 상단 권한 체크 메서드를 통해서 접근을 제어할 수 있다.

- `@PreAuthorize` 내에서 사용가능한 함수/기능들

| 함수/기능                       | 설명                                                              |
| ------------------------------- | ----------------------------------------------------------------- |
| hasRole([role])                 | 현재 사용자의 권한이 파라미터의 권한과 동일한 경우 true           |
| hasAnyRole([role1, role2, ...]) | 현재 사용자의 권한이 파라미터의 권한 중 하나와 일치하는 경우 true |
| principal                       | 사용자를 증명하는 주요 객체(User)에 직접 접근 가능                |
| authentication                  | SecurityContext에 있는 authentication 객체에 접근 가능            |
| permitAll                       | 모든 접근을 허용                                                  |
| denyAll                         | 모든 접근을 거부                                                  |
| isAnonymous()                   | 현재 사용자가 익명(비로그인) 상태인 경우 true                     |
| isRememberMe()                  | 현재 사용자가 RememberMe 사용자인 경우 true                       |
| isAuthenticated()               | 현재 사용자가 익명이 아니고 (로그인 상태인 경우) true             |
| isFullyAuthenticated()          | 현재 사용자가 익명이 아니고 RememberMe 사용자가 아닌 경우 true    |

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
    authentication.getAuthorities().stream().forEach(log::info);
    return ResponseEntity.ok("manager Access!!");
  }

  @GetMapping("/admin")
  @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
  public ResponseEntity adminAccess(Authentication authentication){
    authentication.getAuthorities().stream().forEach(log::info);
    return ResponseEntity.ok("admin Access!!");
  }
}
```

## 8 ) Refresh Token

- 사용자의 Access Token이 만료된 요청인 경우 새로운 Access Token을 발급해주는 토큰이다.
- 흐름
  - 1 . Client : 로그인
  - 2 . Server : 유효한 자격 증명을 검사 후 `Access Token`과 `Refresh Token` 발급
    - Refresh Token 생성 과 동시에 DB에 저장 ( `Access Token`의 유효 시간이 짧음으로 자주 접근이 예상 `Redis`를 추천 )
  - 3 . Client : 모든 요청에 `Access Token`을 Header에 담아 전달
  - 4 . Server : 해당 `Access Token`의 기간이 만료 되었을 경우 인증 오류 반환
  - 5 . Client : 지정된 인증 오류를 받을 경우 Client 측에서는 보유 하고있던 `Refesh Token`을 사용해서 새로운 토큰 요청
  - 6 . Server : 해당 `Refresh Token`의 만료 여부 확인
    - ℹ️ (만료 경우) : 두개의 토큰 모두 만료일 경우 지정된 인증 오류 반환
    - ℹ️ ( 인증 완료 경우 ) : 새로운 `Access Token` 발급
  - 7 . Client : **2번** 부터 다시 **반복**

### 8 - 1 ) Redis 적용

#### 8 - 1 - A ) build.gradle

```groovy
dependencies {
    // Redis
    implementation 'org.springframework.boot:spring-boot-starter-data-redis'
}
```

#### 8 - 1 - B ) application.yml
```properties
spring:
############################
## Redis Setting
# docker Set
# docker run -d --name security-redies-db -p 6379:6379 redis --requirepass "123"
############################
  data:
    redis:
      host: localhost
      port: 6379
      password: 123
```

#### 8 - 1 - C ) Redis Config

```java
@Configuration
/**
 * ℹ️ 필수 설정
 * - Redis 데이터베이스와 상호 작용할 수 있는 구현체를 생성합니다.
 * - Redis 리포지토리를 활성화하면, Spring IoC 컨테이너가 관련된 빈을 생성하고 관리합니다.
 */
@EnableRedisRepositories
public class RedisConfig {
    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    @Value("${spring.data.redis.password}")
    private String redisPassword;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        // 독립형 Redis 인스턴스에 대한 연결 설정을 위한 인스턴스 생성
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        // 호스트 주소 설정
        redisStandaloneConfiguration.setHostName(redisHost);
        // 포트번호 설정
        redisStandaloneConfiguration.setPort(redisPort);
        // 패스워드 설정
        redisStandaloneConfiguration.setPassword(redisPassword);
        // Lettuce Redis 클라이언트를 사용하여 Redis에 연결하는 데 사용됩니다.
        return new LettuceConnectionFactory(redisStandaloneConfiguration);
    }

    @Bean
    public RedisTemplate<String, String> redisTemplate() {
        // 사용할 RedisTemplate 객체 생성
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        // RedisTemplate이 사용할 Connection Factory를 설정합니다. 앞서 정의한 Redis 연결 팩토리를 생성하는 메서드를 적용
        redisTemplate.setConnectionFactory(this.redisConnectionFactory());
        // Key Serializer를 설정합니다. 문자열을 직렬화합니다.
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        // Value Serializer를 설정합니다. 문자열을 직렬화합니다
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        return redisTemplate;
    }
}
```

### 8 - 2 ) Redis를 사용한 Refresh Token 흐름 ( 서버 관점 )
- 1 . 로그인 요청이 들어옴
- 인증 성공 시ss
- `Access Token` 및 `Refresh Token` 발급
- `Refresh Token` Redis에 저장 **( 유효시간을 Reids 데이터 유지 시간과 같게 저장 )**
    - Key 값은 계정ID로 지정
- 2 . 새로운 토큰 발급 요청이 들어옴
- `Access Token` 과 `Refresh Token`을 Parameter로 받음
    - `Access Token`울 받는 이유는 해당 Token **내부의 계정 정보를 활용 하기 위함**
      - Parameter로 계정 정보를 받는거 자체가 안전성 측면에서 떨어진다 판단
- `Refresh Token`의 만료 기간 확인
- `Refresh Token`의 Redis에 저장 유무 및 같은 값인지 확인 ( 교차 검증을 통해 안정성 향상 )
- 이상이 없을 경우 `Access Token`를 활용해서 새로운 `Access Token` 와 `Refresh Token` 발급
- `Refresh Token` Redis에 저장 ( 유효시간을 Reids 데이터 유지 시간과 같게 저장하자 )
    - Key 값은 계정ID로 지정

### 8 - 2 - A ) Controller - 로그인
- 토큰 생성
```java
public class MemberController {
  // Spring Security Manager
  private final AuthenticationManagerBuilder authenticationManagerBuilder;
  // Jwt Util
  private final JwtUtil jwtUtil;
  // ℹ️ Redis 의존성 주입
  private final RedisTemplate<String, String> redisTemplate;

  @PostMapping("/login")
  public ResponseEntity login(@RequestBody LoginDTO loginDTO){
    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getId()
            , loginDTO.getPassword());
    Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
    JwtToken token = jwtUtil.generateToken(authentication);

    // ℹ️ Redis사용을 위한 객체 생성
    ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
    // ℹ️ set()함수를 사용해서 (Key, Value, 적용 시간, 시간방식) 형태로 저장
    valueOperations.set( authentication.getName(), token.getRefreshToken(), 300L, TimeUnit.SECONDS);
    return ResponseEntity.ok().body(token);
  }
}
```
### 8 - 2 - B ) 신규 토큰 발급 - Refresh token 활용

```java
public class MemberController {
    // Jwt Util
    private final JwtUtil jwtUtil;
    // ℹ️ Redis 의존성 주입
    private final RedisTemplate<String, String> redisTemplate;

    @PostMapping("/new-token")
    public ResponseEntity newToken(@RequestBody NewTokenReq newTokenReq){
      boolean validationCheck = jwtUtil.validateToken(newTokenReq.getRefreshToken());
      if(!validationCheck) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("잘못된 토큰입니다");
      // 이전 토큰에서 Claims 값 추출
      Claims oldClaims =  jwtUtil.parseClaims(newTokenReq.getOldAccessToken());
      // 계정Id 추출
      String memberId = oldClaims.get("memberId").toString();
      // ℹ️ Redis 내부에서 저장된 Refresh Token 추출 - 계정 정보로 저장된 Refresh Token 추출
      String refreshToken = redisTemplate.opsForValue().get(memberId);
      // 값이 같은지 확인 후 예외 처리
      if(!newTokenReq.getRefreshToken().equals(refreshToken))
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("재로그인 필요");
      // ℹ️ 만료된 Access Token의 계정정보를 사용해서 새로 토큰생성
      JwtToken newJwtToken = jwtUtil.generateNewToken(oldClaims);
      // ℹ️ Redies에 Refresh Token 정보 업데이트
      ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
      valueOperations.set( memberId, newJwtToken.getRefreshToken(), 300L, TimeUnit.SECONDS);

      return ResponseEntity.ok(newJwtToken);
    }
}
```

## 9 ) 소셜 로그인 (Google) - 기본 설정 대로 사용

### 9 - 1 ) build.gradle

```groovy
// OAuth2 client 추가
implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
```

### 9 - 2 ) application.yml
- ⭐️ 필수 ) Google에서 해당 로그인 API사용 승인을 받아야 함
  - 승인 후 알려주는 clientId 와 sercrtId를 적용
```yaml
spring:
  # yml 구조를 잘 보자 .. spring 아래의 계층으로 security가 들어갔어야 했으나 복붙으로 인한 이슈로 삽질..
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: {id}
            client-secret: {secret}
            scope:
              - email
              - profile
```

### 9 - 3 ) Security Config
- `oauth2Login()`적용을 해주지 않으면 접근이 불가능하다.
  - `{{도메인}}/oauth2/authorization/google`으로 접근하면 자동으로 Google 로그인 연결 페이지로 이동 된다.
  - 승인된 리디렉션으로 `{{도메인}}/login/oauth2/code/google`을 추가해 주자!
    - 기본 설정 그대로 사용하면 해당 Path 정보로 이동하기 떄문이다.
```java
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@Log4j2
public class SecurityConfig {
   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // ℹ️ Google Login 가능 설정
        http.oauth2Login(Customizer.withDefaults());
     return http.build();
   }
}
```

### 9 - 4 ) DefaultOAuth2UserService
- OAuth2 소셜 로그인 사용자 정보를 로드하는 서비스 역할을 진행
  - Spring Security에서 제공하는 DefaultOAuth2UserService를 상속받아 OAuth2 로그인 시 사용자 정보를 가져오는 역할을 합니다.
  - OAutg2 로그인이 성공했을 경우 해당 class의 로직이 실행 된다.
- DefaultOAuth2UserService는 Interface가 아니기에 상속을 통한 구현을 진행 **따로 Security에 설정해 줄 필요가 없다.**
- 로그인에 접근할 경우 해당 로그인에 대한 정보를 알 수 있다.
```console
Key :: sub ,  Value ::114903903503988787
Key :: name ,  Value ::유정호
Key :: given_name ,  Value :: lastName
Key :: family_name ,  Value :: firstName
Key :: picture ,  Value :: -
Key :: email ,  Value ::emailAddress
Key :: email_verified ,  Value ::true
Key :: locale ,  Value ::ko
```

```java
/**
 * ⭐️ 특별한 설정 없이도 자동으로 OAuth 로그인시 해당 Service 사용
 * - 상속을 통해 이뤄졌기 떄문이다!
 * ( UserDetailsService의 경우 Interface를 구현했기에 따로 SecurityConfig에서 등록이 필요 했던 것! )
 * */
@Service
@Log4j2
public class OAuth2UserDetailsService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("-------------------------");
        log.info(" OAuth Social Login Service");
        log.info("-------------------------");

        // OAuth에 사용된 Client Name => 현 테스틑 Goolge Social Login이기에 Goole 출력
        log.info("clientName :: {}",userRequest.getClientRegistration().getClientName());
        // id_token 값을 확인 할 수 있다.
        log.info("additionalParameters ::: {}",userRequest.getAdditionalParameters());

        //반환 객요청 : sub, picture, email, email_verified(이메일 확인) 정보를 갖고 있다.
        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("-----------------------------");
        oAuth2User.getAttributes().forEach((k,v)->{
            log.info("Key :: {} ,  Value ::{}",k,v);
        });
        log.info("-----------------------------");

        return super.loadUser(userRequest);
    }
}
```

### 9 - 5 ) Custom OAuth Success Handler 구현

#### 9 - 5 - A ) Custom AuthenticationSuccessHandler Class

```java
@Log4j2
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("----------------------------");
        log.info("OAuth Success!!!!!");
        log.info("----------------------------");

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"token\": \"" + "test!!" + "\"}");
    }
}
```

#### 9 - 5 - B ) Security Config

```java
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@Log4j2
public class SecurityConfig {
  // 의존성 주입
  private final OAuth2SuccessHandler oAuth2SuccessHandler;

   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // ℹ️ Google Login 가능 설정
        http.oauth2Login(Customizer.withDefaults());
        // 적용
        http.oauth2Login(oauth -> oauth.successHandler(oAuth2SuccessHandler));
        return http.build();
    }
}
```

## 10 ) 소셜 로그인 (Google) - API 방식 사용

- Jwt Token을 사용하여 인증 처리할 경우 일반적인 OAuth 로그인 방식으로는 사용이 불가능하기에 API 방식으로 사용한다.

### 10 - 1 ) 흐름
- [Client] 지정 URL로 소셜 요청
- [Server] 서버에 저장된 `scope`,`client_id`,`redirect_uri`를 통해 URI를 만들어 서드파티(Google)로 `sendRedirect()` 시킴
  - 해당 리디렉션 URI는 Google에 등록되어 있어야 한다.
  - [공식 문서](https://developers.google.com/identity/protocols/oauth2/web-server?hl=ko#libraries) 확인
- [Google] 지정 Goolge 계정 검증 후 리디렉션으로 code를 보내줌
- [Server] 만들어 놓은 Conroller를 통해 전달받은 `code`와 이미 갖고 있던 `client_id, client_secret, redirect_uri`를 사용해서 인증 파라미터 생성 후 Google과 연계 작업
- [Google] 전달 받은 Body값을 통해 토큰을 발행
- [Server] 받아온 Token을 통해 Google로 정보 요청
- [Google] 토큰 검증 후 데이터 반환
- [Server] 해당 인증 정보를 통해 신규 가입 혹은 해당 서버에서 사용할 Token 발행


#### 10 - 1 - A ) Redirect 반환 받을 Controller

- 소셜 인증을 요청을 받을 Controller

```java
@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/app/accounts")
public class SocialController {

    private final OAuthService oAuthService;

    @GetMapping("/auth/{type}")
    public void socialLoginRedirect(@PathVariable String type) throws IOException {
        log.info("-----------");
        log.info("socialType :::" + type);
        log.info("-----------");
        oAuthService.request(type);
    }
}
```

#### 10 - 1 - B ) Social Type에 맞게 리다이렉트를 시켜줄 Service
- socialLoginRedirect에서 전달 받은 값을 사용하여 로직 진행
- `HttpServletResponse`를 의존성 주입을 통해 리다이렉션 메서드를 사용

```java
@Service
@RequiredArgsConstructor
public class OAuthService {
    private final GoogleOauth googleOauth;
    private final HttpServletResponse response;

    public void request(String type) throws IOException {
        // 👉 Redirection 시킬 URL
        String redirectURL;
        // 👉 Social enum 변환
        SocialType socialType = SocialType.valueOf(type.toUpperCase());
        switch (socialType){
            case GOOGLE:
                // 👉 리다이렉트 시킬 URL을 생성
                redirectURL = googleOauth.getOauthRedirectURL();
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }// switch
        response.sendRedirect(redirectURL);
    }
}
```

#### 10 - 1 - C ) Social 구분 별 리디렉션 URL을 만들 메서드를 강제할 Interface
- 필수로 필요한 Interfacer는 아니지만, **확장성을 위해서 Interface를 분리해서 사용**

```java
public interface SocialOAuth {
    /**
     * 각 소셜 로그인 페이지로 redirect 할 URL build
     * 사용자로부터 로그인 요청을 받아 소셜 로그인 서버 인증용 코드 요청
     */
    String getOauthRedirectURL();
}
```

#### 10 - 1 - B ) 소셜 형식에 맞는 요청 class
- SocialOAuth를 implements 하여`getOauthRedirectURL()`를 구현
- 내가 사용하려는 **소셜의 api 형식에 맞는 값을 구현하여 요청**을 보내야한다. ( 예제에서는 Google로 진행 )

```java
@Component
@Log4j2
@RequiredArgsConstructor
public class GoogleOauth implements SocialOAuth{
    // https://accounts.google.com/o/oauth2/v2/auth
    @Value("${spring.OAuth2.google.url}")
    private String GOOGLE_SNS_LOGIN_URL;
    // 인증 ID
    @Value("${spring.OAuth2.google.client-id}")
    private String GOOGLE_SNS_CLIENT_ID;
    // 지정한 리디렉션 URL
    @Value("${spring.OAuth2.google.callback-url}")
    private String GOOGLE_SNS_CALLBACK_URL;
    // scope는 아래처럼 공백으로 되어 URL 에서 `%20`로 붙어서 처리된다.
    @Value("${spring.OAuth2.google.scope}")
    private String GOOGLE_DATA_ACCESS_SCOPE;

    @Override
    public String getOauthRedirectURL() {
        // 👉 파라미터 정의
        Map<String, String> params = new HashMap<>();
        params.put("scope"          , GOOGLE_DATA_ACCESS_SCOPE);
        params.put("response_type"  , "code");
        params.put("client_id"      , GOOGLE_SNS_CLIENT_ID);
        params.put("redirect_uri"   , GOOGLE_SNS_CALLBACK_URL);

        // 👉 파라미터를 URL 형식으로 변경
        String parameterString = params.entrySet()
                .stream()
                .map(x->x.getKey()+"="+x.getValue())
                .collect(Collectors.joining("&"));

        // 👉 리디렉션시킬 URL에 파라미터 추가
        String redirectURL = GOOGLE_SNS_LOGIN_URL + "?" + parameterString;
        /***
         * https://accounts.google.com/o/oauth2/v2/auth
         * ?scope=https://www.googleapis.com/auth/userinfo.email
         * %20https://www.googleapis.com/auth/userinfo.profile&response_type=code
         * &redirect_uri=http://localhost:8080/app/accounts/auth/google/callback
         * &client_id=824915807954-ba1vkfj4aec6bgiestgnc0lqrbo0rgg3.apps.googleusercontent.com
         * **/
        log.info("-------------------");
        log.info("redirectURL = " + redirectURL);
        log.info("-------------------");
        return redirectURL;
    }
}
```

### 10 - 2 ) 인증 확인 후 로직

```properties
#- Google에서 인증이 완료되면 지정한 `redirect`로 응답을 보낸다.
#- 해당 로직에서 계정에 관련된 비즈니스 로직을 구현해주면 된다
#- 토큰 발급 또는 회원가입 로직 등 다양하게 구현이 가능하다.
```

### 10 - 2 - A ) 인증 완료 후 리디렉션을 받을 Controller

- Google 자체의 회원 검증 후 내가 지정했던 callback url로 코드를 반환 해주면 받을 서버의 Controller Path를 지정 해주는 것임

```java
@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/app/accounts")
public class SocialController {

    private final OAuthService oAuthService;

    @ResponseBody
    @GetMapping(value = "/auth/{type}/callback")
    public ResponseEntity<GetSocialOAuthRes> callback ( @PathVariable String type
            , @RequestParam String code) throws Exception{
        log.info(">> 소셜 로그인 API 서버로부터 받은 code :"+ code);
        return ResponseEntity.ok(oAuthService.oAuthLogin(type, code));
    }

}
```

### 10 - 3 ) 소셜 로그인 비즈니스로직 Service

```java
@Service
@RequiredArgsConstructor
@Log4j2
public class OAuthService {
  private final GoogleOauth googleOauth;

  public JwtToken oAuthLogin(String type, String code) throws IOException {
        // 👉 Social enum 변환
        SocialType socialType = SocialType.valueOf(type.toUpperCase());
        switch (socialType) {
            case GOOGLE:
                /**
                 * 👉 일회성 코드를 사용해 토큰을 받음 이를 deserialization해서 자바 객체로 변경
                 * */
                GoogleOAuthToken oAuthToken = googleOauth.requestAccessToken(code);
                /**
                 * 👉 액세스 토큰을 다시 구글로 보내 사용자 정보를 받음 이를 deserialization해서 자바 객체로 변경
                 * */
                GoogleUser googleUser = googleOauth.requestUserInfo(oAuthToken);
                // ℹ️ 해당 받아온 값을 토대로 회원 DB관련 로직을 적용하자
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }// switch - case

        // TODO 받아온 데이터를 사용해서 반환 데이터를 만들어주자
        return JwtToken.builder()
                .accessToken("엑세스 토큰 발급")
                .refreshToken("리프레쉬 토큰 발급")
                .grantType("Bearer")
                .build();
    }

}
```

### 10 - 4 ) Google과 연계 가능한 기능

- 필요한 정보를 요청하는 URL은 공식 문서에서 확인이 가능하다.

```java
@Component
@Log4j2
@RequiredArgsConstructor
public class GoogleOauth implements SocialOAuth{

    @Value("${spring.OAuth2.google.url}")
    private String GOOGLE_SNS_LOGIN_URL;

    @Value("${spring.OAuth2.google.client-id}")
    private String GOOGLE_SNS_CLIENT_ID;

    @Value("${spring.OAuth2.google.callback-url}")
    private String GOOGLE_SNS_CALLBACK_URL;

    @Value("${spring.OAuth2.google.client-secret}")
    private String GOOGLE_SNS_CLIENT_SECRET;

    private final ObjectMapper objectMapper;

    /**
     * Google에서 인증받은 일회성 코드을 연계에 사용하여 인증 jwt 토큰을 받아옴
     *
     * @param code the code
     * @return the response entity
     */
    public GoogleOAuthToken requestAccessToken(String code) throws JsonProcessingException{
        // ℹ️ 토큰 요청 URL - 공식문서 확인
        String GOOGLE_TOKEN_REQUEST_URL = "https://oauth2.googleapis.com/token";
        RestTemplate restTemplate       = new RestTemplate();
        Map<String, Object> params      = new HashMap<>();
        params.put("code", code);
        params.put("client_id"      , GOOGLE_SNS_CLIENT_ID);
        params.put("client_secret"  , GOOGLE_SNS_CLIENT_SECRET);
        params.put("redirect_uri"   , GOOGLE_SNS_CALLBACK_URL);
        params.put("grant_type"     , "authorization_code");

        // 👉 Google 연계 시작
        ResponseEntity<String> responseEntity =
                restTemplate.postForEntity(GOOGLE_TOKEN_REQUEST_URL, params, String.class);
        // ℹ️ 2xx가 아니면 null 반환
        if(responseEntity.getStatusCode() != HttpStatus.OK) return null;

        // Google에서 받아온 Response Body 데이터
        log.info("response.getBody() = " + responseEntity.getBody());
        /***
         * {
         *   "access_token": "~",
         *   "expires_in": 3598,
         *   "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
         *   "token_type": "Bearer",
         *   "id_token": "~"
         * }
         *
         * **/
        // 자바 객체로 변환
        return objectMapper.readValue(responseEntity.getBody(), GoogleOAuthToken.class);

    }

    /**
     * Google에서 발행한 jwt 토큰을 사용해서 회원 정보를 받아옴
     *
     * @param oAuthToken the o auth token
     * @return the google user
     */
    public GoogleUser requestUserInfo(GoogleOAuthToken oAuthToken)  throws JsonProcessingException{
        // ℹ️ 회원정보 요청 URL - 공식문서 확인 [ AccessToken 필요 ]
        String GOOGLE_USERINFO_REQUEST_URL = "https://www.googleapis.com/oauth2/v1/userinfo";

        // 👉 Header에 jwt 토큰을 담음
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION,"Bearer " + oAuthToken.getAccess_token());

        // 👉 Google과 연계
        RestTemplate restTemplate       = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(GOOGLE_USERINFO_REQUEST_URL, HttpMethod.GET,request,String.class);
        log.info("response.getBody() = " + response.getBody());
        /**
         * {
         *   "id": "~~~",
         *   "email": "~",
         *   "verified_email": true,
         *   "name": "유정호",
         *   "given_name": "정호",
         *   "family_name": "유",
         *   "picture": "~",
         *   "locale": "ko"
         * }
         * **/
        return objectMapper.readValue(response.getBody(), GoogleUser.class);
    }

}
```
