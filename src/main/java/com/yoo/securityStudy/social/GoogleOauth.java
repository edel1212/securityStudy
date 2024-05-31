package com.yoo.securityStudy.social;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yoo.securityStudy.dto.google.GoogleOAuthToken;
import com.yoo.securityStudy.dto.google.GoogleUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class GoogleOauth implements SocialOAuth{

    @Value("${spring.OAuth2.google.url}")
    private String GOOGLE_SNS_LOGIN_URL;

    @Value("${spring.OAuth2.google.client-id}")
    private String GOOGLE_SNS_CLIENT_ID;

    @Value("${spring.OAuth2.google.callback-url}")
    private String GOOGLE_SNS_CALLBACK_URL;

    @Value("${spring.OAuth2.google.client-secret}")
    private String GOOGLE_SNS_CLIENT_SECRET;

    @Value("${spring.OAuth2.google.scope}")
    private String GOOGLE_DATA_ACCESS_SCOPE;

    private final ObjectMapper objectMapper;

    @Override
    public String getOauthRedirectURL() {
        // 👉 파라미터 정의
        Map<String, String> params = new HashMap<>();
        params.put("scope"          , GOOGLE_DATA_ACCESS_SCOPE);
        params.put("response_type"  , "code");
        params.put("client_id"      , GOOGLE_SNS_CLIENT_ID);
        params.put("redirect_uri"   , GOOGLE_SNS_CALLBACK_URL);

        // 👉 파라미터를 URL 형식으로 변경
        String parameterString = params.entrySet()
                .stream()
                .map(x->x.getKey()+"="+x.getValue())
                .collect(Collectors.joining("&"));

        // 👉 리디렉션시킬 URL에 파라미터 추가
        String redirectURL = GOOGLE_SNS_LOGIN_URL + "?" + parameterString;
        /***
         * https://accounts.google.com/o/oauth2/v2/auth
         * ?scope=https://www.googleapis.com/auth/userinfo.email
         * %20https://www.googleapis.com/auth/userinfo.profile&response_type=code
         * &redirect_uri=http://localhost:8080/app/accounts/auth/google/callback
         * &client_id=824915807954-ba1vkfj4aec6bgiestgnc0lqrbo0rgg3.apps.googleusercontent.com
         * **/
        log.info("-------------------");
        log.info("redirectURL = " + redirectURL);
        log.info("-------------------");
        return redirectURL;
    }

    public ResponseEntity<String> requestAccessToken(String code) {
        String GOOGLE_TOKEN_REQUEST_URL = "https://oauth2.googleapis.com/token";
        RestTemplate restTemplate       = new RestTemplate();
        Map<String, Object> params      = new HashMap<>();
        params.put("code", code);
        params.put("client_id"      , GOOGLE_SNS_CLIENT_ID);
        params.put("client_secret"  , GOOGLE_SNS_CLIENT_SECRET);
        params.put("redirect_uri"   , GOOGLE_SNS_CALLBACK_URL);
        params.put("grant_type"     , "authorization_code");

        ResponseEntity<String> responseEntity =
                restTemplate.postForEntity(GOOGLE_TOKEN_REQUEST_URL, params, String.class);

        if(responseEntity.getStatusCode() == HttpStatus.OK){
            return responseEntity;
        }
        return null;
    }

    public GoogleOAuthToken getAccessToken(ResponseEntity<String> response) throws JsonProcessingException {
        // Google에서 받아온 Response Body 데이터
        log.info("response.getBody() = " + response.getBody());
        // GoogleOAuthToken 변환
        return objectMapper.readValue(response.getBody(),GoogleOAuthToken.class);

    }

    public ResponseEntity<String> requestUserInfo(GoogleOAuthToken oAuthToken) {
        String GOOGLE_USERINFO_REQUEST_URL = "https://www.googleapis.com/oauth2/v1/userinfo";

        //header에 accessToken을 담는다.
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization","Bearer " + oAuthToken.getAccess_token());

        //HttpEntity를 하나 생성해 헤더를 담아서 restTemplate으로 구글과 통신하게 된다.
        RestTemplate restTemplate       = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(GOOGLE_USERINFO_REQUEST_URL, HttpMethod.GET,request,String.class);
        log.info("response.getBody() = " + response.getBody());
        return response;
    }

    public GoogleUser getUserInfo(ResponseEntity<String> userInfoRes) throws JsonProcessingException{
        return objectMapper.readValue(userInfoRes.getBody(), GoogleUser.class);
    }

}
