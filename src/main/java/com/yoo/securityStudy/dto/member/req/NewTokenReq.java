package com.yoo.securityStudy.dto.member.req;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
public class NewTokenReq {
    // 기간이 만료된 오래된 토큰
    private String oldAccessToken;
    // Refresh Token
    private String refreshToken;
}
