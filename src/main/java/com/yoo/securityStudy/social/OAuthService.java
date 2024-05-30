package com.yoo.securityStudy.social;

import com.yoo.securityStudy.dto.google.GoogleOAuthToken;
import com.yoo.securityStudy.dto.google.GoogleUser;
import com.yoo.securityStudy.dto.social.GetSocialOAuthRes;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
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
                //각 소셜 로그인을 요청하면 소셜로그인 페이지로 리다이렉트 해주는 프로세스이다.
                redirectURL= googleOauth.getOauthRedirectURL();
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }// switch
        response.sendRedirect(redirectURL);
    }

    public GetSocialOAuthRes oAuthLogin(String type, String code) throws IOException {
        // 👉 Social enum 변환
        SocialType socialType = SocialType.valueOf(type.toUpperCase());
        switch (socialType) {
            case GOOGLE:
                //구글로 일회성 코드를 보내 액세스 토큰이 담긴 응답객체를 받아옴
                ResponseEntity<String> accessTokenResponse = googleOauth.requestAccessToken(code);
                //응답 객체가 JSON형식으로 되어 있으므로, 이를 deserialization해서 자바 객체에 담을 것이다.
                GoogleOAuthToken oAuthToken = googleOauth.getAccessToken(accessTokenResponse);
                //액세스 토큰을 다시 구글로 보내 구글에 저장된 사용자 정보가 담긴 응답 객체를 받아온다.
                ResponseEntity<String> userInfoResponse = googleOauth.requestUserInfo(oAuthToken);
                //다시 JSON 형식의 응답 객체를 자바 객체로 역직렬화한다.
                GoogleUser googleUser = googleOauth.getUserInfo(userInfoResponse);
                break;
            default:
                throw new IllegalArgumentException("알 수 없는 소셜 로그인 형식입니다.");
        }
        return new GetSocialOAuthRes("abc",1, "asd", "Google");
    }

}
