package com.yoo.securityStudy.social;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

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
        Map<String, String> params = new HashMap<>();
        params.put("scope"          , GOOGLE_DATA_ACCESS_SCOPE);
        params.put("response_type"  , "code");
        params.put("client_id"      , GOOGLE_SNS_CLIENT_ID);
        params.put("redirect_uri"   , GOOGLE_SNS_CALLBACK_URL);

        //parameter를 형식에 맞춰 구성해주는 함수
        String parameterString = params.entrySet()
                .stream()
                .map(x->x.getKey()+"="+x.getValue())
                .collect(Collectors.joining("&"));

        String redirectURL = GOOGLE_SNS_LOGIN_URL+"?"+parameterString;
        log.info("-------------------");
        log.info("redirectURL = " + redirectURL);
        log.info("-------------------");
        return redirectURL;
    }
}
