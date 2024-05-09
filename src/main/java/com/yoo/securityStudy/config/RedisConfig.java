package com.yoo.securityStudy.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
/**
 * ℹ️ 필수 설정
 * - Redis 데이터베이스와 상호 작용할 수 있는 구현체를 생성합니다.
 * - Redis 리포지토리를 활성화하면, Spring IoC 컨테이너가 관련된 빈을 생성하고 관리합니다.
 */
@EnableRedisRepositories
public class RedisConfig {
    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    @Value("${spring.data.redis.password}")
    private String redisPassword;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        // 독립형 Redis 인스턴스에 대한 연결 설정을 위한 인스턴스 생성
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        // 호스트 주소 설정
        redisStandaloneConfiguration.setHostName(redisHost);
        // 포트번호 설정
        redisStandaloneConfiguration.setPort(redisPort);
        // 패스워드 설정
        redisStandaloneConfiguration.setPassword(redisPassword);
        // Lettuce Redis 클라이언트를 사용하여 Redis에 연결하는 데 사용됩니다.
        return new LettuceConnectionFactory(redisStandaloneConfiguration);
    }

    @Bean
    public RedisTemplate<String, String> redisTemplate() {
        // 사용할 RedisTemplate 객체 생성
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        // RedisTemplate이 사용할 Connection Factory를 설정합니다. 앞서 정의한 Redis 연결 팩토리를 생성하는 메서드를 적용
        redisTemplate.setConnectionFactory(this.redisConnectionFactory());
        // Key Serializer를 설정합니다. 문자열을 직렬화합니다.
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        // Value Serializer를 설정합니다. 문자열을 직렬화합니다
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        return redisTemplate;
    }
}
