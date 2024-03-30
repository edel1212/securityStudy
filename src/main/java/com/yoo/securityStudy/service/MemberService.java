package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberDTO;
import com.yoo.securityStudy.entity.Member;
import com.yoo.securityStudy.entity.enums.Roles;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public interface MemberService {
    MemberDTO registerMember(MemberDTO memberDTO);

    MemberDTO registerMember_passwordEncoder(MemberDTO memberDTO);

    default Member dtoToEntity(MemberDTO memberDTO){
        return Member.builder()
                .id(memberDTO.getId())
                .password(memberDTO.getPassword())
                .name(memberDTO.getName())
                .roles(memberDTO.getRoles())
                .build();
    }

    default MemberDTO entityToDto(Member member){
        return new MemberDTO(member.getId(), member.getPassword(), member.getName(), this.authorities(member.getRoles()),  member.getRoles());
    }

    // User객체의 형태에 맞는 객체 주입
    default Collection<? extends GrantedAuthority> authorities(Set<Roles> roles){
        return roles.stream()
                //  "ROLE_" 접두사를 사용하는 이유는  Spring Security가 권한을 인식하고 처리할 때 해당 권한이 역할임을 명확하게 나타내기 위한 관례입니다.
                .map(r -> new SimpleGrantedAuthority("ROLE_"+r.name()))
                .collect(Collectors.toSet());
    }

}
