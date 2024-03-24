package com.yoo.securityStudy.dto;

import com.yoo.securityStudy.entity.enums.Roles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class MemberDTO {
    private String id;
    private String password;
    private String name;
    private Set<Roles> roles;
}
