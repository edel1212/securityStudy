package com.yoo.securityStudy.controller;

import com.yoo.securityStudy.dto.LoginDTO;
import com.yoo.securityStudy.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping(value = "/member", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@RestController
public class MemberController {

    private final UserDetailsService userDetailsService;
    private final MemberService memberService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDTO loginDTO){
        userDetailsService.loadUserByUsername(loginDTO.getId());
        return ResponseEntity.ok().body("Hi");
    }

}
