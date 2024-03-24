package com.yoo.securityStudy.repository;

import com.yoo.securityStudy.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {
}
