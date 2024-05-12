package com.yoo.securityStudy.controller;

import com.yoo.securityStudy.config.JwtUtil;
import com.yoo.securityStudy.dto.LoginDTO;
import com.yoo.securityStudy.dto.member.req.NewTokenReq;
import com.yoo.securityStudy.security.dto.JwtToken;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

@RequestMapping(value = "/member", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@RestController
@Log4j2
public class MemberController {

    // Spring Security Manager
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    // Jwt Util
    private final JwtUtil jwtUtil;
    // Redis
    private final RedisTemplate<String, String> redisTemplate;

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

        log.info("-----------");
        log.info("로그인 성공 - 로그인Id ::: " + authentication.getName() );
        log.info("-----------");
        JwtToken token = jwtUtil.generateToken(authentication);

        // 3 . Redis에 Refresh Token 저장 0 5분
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set( authentication.getName(), token.getRefreshToken(), 300L, TimeUnit.SECONDS);
       return ResponseEntity.ok().body(token);
    }

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
