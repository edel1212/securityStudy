package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberDTO;
import com.yoo.securityStudy.entity.enums.Roles;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Log4j2
class MemberServiceImplTest {

    @Autowired
    private MemberService memberService;

    @Test
    @DisplayName("회원 저장 - password encoder 미적용")
    void registerMember_NO_USEED_PASSWORD_ENCODER() {
        String yoo = "yoo";
        String password = "123";
        Set<Roles> rolesSet = Set.of(Roles.ADMIN, Roles.USER);
        String name = "흑곰";
        MemberDTO memberDTO = MemberDTO.builder()
                .id(yoo)
                .name(name)
                .password(password)
                .roles(rolesSet)
                .build();

        MemberDTO registerMember = memberService.registerMember(memberDTO);
        assertThat(registerMember.getId()).isEqualTo(yoo);
        assertThat(registerMember.getPassword()).isEqualTo(password);
        assertThat(registerMember.getName()).isEqualTo(name);
        assertThat(registerMember.getRoles()).containsAll(rolesSet);
    }
}