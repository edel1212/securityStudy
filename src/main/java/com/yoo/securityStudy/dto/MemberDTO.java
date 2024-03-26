package com.yoo.securityStudy.dto;

import com.yoo.securityStudy.entity.enums.Roles;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Set;

@Getter
@Setter
@ToString
public class MemberDTO extends User {
    private String id;
    private String password;
    private String name;
    private Set<Roles> roles;

    @Builder
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
