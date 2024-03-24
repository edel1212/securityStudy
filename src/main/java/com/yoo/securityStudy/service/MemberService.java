package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberDTO;
import com.yoo.securityStudy.entity.Member;

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
        return MemberDTO.builder()
                .id(member.getId())
                .password(member.getPassword())
                .name(member.getName())
                .roles(member.getRoles())
                .build();
    }
}
