package com.yoo.securityStudy.entity;

import com.yoo.securityStudy.entity.enums.Roles;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Member {
    @Id
    private String id;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    // ⭐️ ElementCollection을 사용해줘야 컬렉션 형태를 1 : N 테이블을 생성해준다.
    @ElementCollection(fetch = FetchType.LAZY)
    @Builder.Default
    @Column(nullable = false)
    private Set<Roles> roles = new HashSet<>();
}
