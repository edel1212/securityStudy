package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberDTO;
import com.yoo.securityStudy.entity.Member;
import com.yoo.securityStudy.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Log4j2
public class MemberServiceImpl implements MemberService{

    private final MemberRepository memberRepository;

    @Override
    public MemberDTO registerMember(MemberDTO memberDTO) {
        Member member = memberRepository.save(this.dtoToEntity(memberDTO));
        return this.entityToDto(member);
    }
}
