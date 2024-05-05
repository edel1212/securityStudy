package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.member.req.SignUpReq;
import com.yoo.securityStudy.dto.member.res.SignUpRes;
import com.yoo.securityStudy.entity.enums.Roles;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Log4j2
class MemberServiceImplTest {

    @Autowired
    private MemberService memberService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("회원 저장 - using password encoder")
    void registerMember_PASSWORD_ENCODER() {
        String id = "admin";
        String password = "123";
        Set<Roles> rolesSet = Set.of(Roles.ADMIN, Roles.MANAGER, Roles.USER);
        String name = "흑곰";
        SignUpReq signUpReq = SignUpReq.builder()
                .id(id)
                .name(name)
                .password(password)
                .roles(rolesSet)
                .build();
        SignUpRes signUpRes = memberService.registerMember(signUpReq);
        assertThat(signUpRes.getId()).isEqualTo(id);
        assertThat(signUpRes.getName()).isEqualTo(name);
        assertThat(signUpRes.getRoles()).containsAll(rolesSet);

        log.info("password 검증");
        log.info(passwordEncoder.matches( password ,signUpRes.getPassword()));
        log.info("------");
    }

}