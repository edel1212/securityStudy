package com.yoo.securityStudy.dto;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class LoginDTO {
    private String id;
    private String password;
}
