package com.yoo.securityStudy.controller;

import com.yoo.securityStudy.config.JwtUtil;
import com.yoo.securityStudy.dto.LoginDTO;
import com.yoo.securityStudy.security.dto.JwtToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        log.info("!!!");
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
