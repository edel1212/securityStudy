package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberToUserDTO;
import com.yoo.securityStudy.dto.member.req.SignUpReq;
import com.yoo.securityStudy.dto.member.res.SignUpRes;
import com.yoo.securityStudy.entity.Member;
import com.yoo.securityStudy.entity.enums.Roles;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public interface MemberService {
    SignUpRes registerMember(SignUpReq signUpReq);

    default Member dtoToEntity(SignUpReq signUpReq){
        return Member.builder()
                .id(signUpReq.getId())
                .password(signUpReq.getPassword())
                .name(signUpReq.getName())
                .roles(signUpReq.getRoles())
                .build();
    }

    // User객체의 형태에 맞는 객체 주입
    default Collection<? extends GrantedAuthority> authorities(Set<Roles> roles){
        return roles.stream()
                //  "ROLE_" 접두사를 사용하는 이유는  Spring Security가 권한을 인식하고 처리할 때 해당 권한이 역할임을 명확하게 나타내기 위한 관례입니다.
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
                , this.authorities(member.getRoles())
                ,  member.getRoles());
    }

    /**
     * Entity -> SignUpRes DTO
     *
     * @param member the member
     * @return the sign up res
     */
    default SignUpRes entityToSignUpRes(Member member){
        return SignUpRes.builder()
                .id(member.getId())
                .password(member.getPassword())
                .name(member.getName())
                .roles(member.getRoles())
                .build();
    }

}
