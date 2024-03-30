package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.MemberDTO;
import com.yoo.securityStudy.entity.Member;
import com.yoo.securityStudy.entity.enums.Roles;
import com.yoo.securityStudy.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class MemberServiceImpl implements MemberService, UserDetailsService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public MemberDTO registerMember(MemberDTO memberDTO) {
        Member member = memberRepository.save(this.dtoToEntity(memberDTO));
        return this.entityToDto(member);
    }

    @Override
    public MemberDTO registerMember_passwordEncoder(MemberDTO memberDTO) {
        memberDTO.setPassword(passwordEncoder.encode(memberDTO.getPassword()));
        Member member = memberRepository.save(this.dtoToEntity(memberDTO));
        return this.entityToDto(member);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("-----------------");
        log.info("로그인 접근");
        log.info("-----------------");

        // 1. userName(아이디)를 기준으로 데이터 존재 확인
        Member member = memberRepository.findById(username)
                .orElseThrow(()->new UsernameNotFoundException(username));

        // 2. 존재한다면 해당 데이터를 기준으로 User객체를 생성 반환
        //    🫵 중요 포인트는 해당 객체를 받아온 후 이후에 password 검증을 진행한다는 것이다
        return this.entityToDto(member);
    }


}
