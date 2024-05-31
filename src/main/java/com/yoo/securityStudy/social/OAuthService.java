package com.yoo.securityStudy.social;

import com.yoo.securityStudy.dto.google.GoogleOAuthToken;
import com.yoo.securityStudy.dto.google.GoogleUser;
import com.yoo.securityStudy.security.dto.JwtToken;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
@Log4j2
public class OAuthService {
    private final GoogleOauth googleOauth;
    private final HttpServletResponse response;

    public void request(String type) throws IOException {
        // 👉 Redirection 시킬 URL
        String redirectURL;
        // 👉 Social enum 변환
        SocialType socialType = SocialType.valueOf(type.toUpperCase());
        switch (socialType){
            case GOOGLE:
                // 👉 리다이렉트 시킬 URL을 생성
                redirectURL = googleOauth.getOauthRedirectURL();
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }// switch
        response.sendRedirect(redirectURL);
    }

    public JwtToken oAuthLogin(String type, String code) throws IOException {
        // 👉 Social enum 변환
        SocialType socialType = SocialType.valueOf(type.toUpperCase());
        switch (socialType) {
            case GOOGLE:
                /**
                 * 👉 일회성 코드를 사용해 토큰을 받음 이를 deserialization해서 자바 객체로 변경
                 * */
                GoogleOAuthToken oAuthToken = googleOauth.requestAccessToken(code);
                /**
                 * 👉 액세스 토큰을 다시 구글로 보내 사용자 정보를 받음 이를 deserialization해서 자바 객체로 변경
                 * */
                GoogleUser googleUser = googleOauth.requestUserInfo(oAuthToken);
                // ℹ️ 해당 받아온 값을 토대로 회원 DB관련 로직을 적용하자
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }// switch - case

        // TODO 받아온 데이터를 사용해서 반환 데이터를 만들어주자
        return JwtToken.builder()
                .accessToken("엑세스 토큰 발급")
                .refreshToken("리프레쉬 토큰 발급")
                .grantType("Bearer")
                .build();
    }

}
