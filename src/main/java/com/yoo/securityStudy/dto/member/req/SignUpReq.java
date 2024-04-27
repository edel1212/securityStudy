package com.yoo.securityStudy.dto.member.req;

import com.yoo.securityStudy.entity.enums.Roles;
import lombok.*;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class SignUpReq {
    private String id;
    private String password;
    private String name;
    private Set<Roles> roles;
}
