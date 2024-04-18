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

## TODO List

- DB 계정 관리
  - 권한별 접근
- 커스텀 핸들러 적용
- jwt
  - Refresh token
