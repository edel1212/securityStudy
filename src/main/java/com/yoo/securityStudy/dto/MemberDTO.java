package com.yoo.securityStudy.dto;

import com.yoo.securityStudy.entity.enums.Roles;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Set;

/**
 * extends User 를 사용하는 이유는 간단하다
 * UserDetails를 반환하는 loadUserByUsername()메서드에서
 * - 아이디, 비밀번호, 권한 << 이렇게 3개만 있으면 User를 사용해도 되지만
 *
 * 그렇지 않을 경우 추가적은 정보를 갖는 경우 아래와 같이 DTO를 추가후 Super()를 통해
 * 부모에게 필요한 생성정보를 전달 하고 나머지는 내가 필요한 정보를 들고 있기 위함이다.
 * */
@Getter
@Setter
@ToString
public class MemberDTO extends User {
    private String id;
    private String password;
    private String name;
    private Set<Roles> roles;

    @Builder(builderClassName = "MemberDTOBuilder")
    public MemberDTO(String id
            , String password
            , Collection<? extends GrantedAuthority> authorities
            , Set<Roles> roles
            , String name) {
        super(id, password, authorities);
        this.id = id;
        this.password = password;
        this.name = name;
        this.roles = roles;
    }

}
