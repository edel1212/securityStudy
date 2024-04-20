package com.yoo.securityStudy.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtToken {
    // Jwt 인증 타입 [ Bearer 사용 ]
    private String grantType;
    // 발급 토근
    private String accessToken;
    // 리프레쉬 토큰
    private String refreshToken;
}
