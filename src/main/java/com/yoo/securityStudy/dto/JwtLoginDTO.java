package com.yoo.securityStudy.dto;

import com.yoo.securityStudy.entity.enums.Roles;
import lombok.*;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class JwtLoginDTO {
    private String memberId;
    private Set<Roles> roles;
}
