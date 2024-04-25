package com.yoo.securityStudy.service;

import com.yoo.securityStudy.dto.member.req.SignUpReq;
import com.yoo.securityStudy.dto.member.res.SignUpRes;
import com.yoo.securityStudy.entity.Member;
import com.yoo.securityStudy.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Log4j2
public class MemberServiceImpl implements MemberService, UserDetailsService {

    private final MemberRepository memberRepository;

    // ⭐️ SecurityConfig에서 Bean 생성 시 cycle 에러가 발생함 - Config용 class 따로 생성
    private final PasswordEncoder passwordEncoder;

    @Override
    public SignUpRes registerMember(SignUpReq signUpReq) {
        signUpReq.setPassword(passwordEncoder.encode(signUpReq.getPassword()));
        Member member = memberRepository.save(this.dtoToEntity(signUpReq));
        return this.entityToSignUpRes(member);
    }

    @Transactional
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
        return this.entityToUserDto(member);
    }


}
