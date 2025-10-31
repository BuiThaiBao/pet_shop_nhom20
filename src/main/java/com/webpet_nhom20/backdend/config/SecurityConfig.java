package com.webpet_nhom20.backdend.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.crypto.spec.SecretKeySpec;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final String[] PUBLIC_POST_ENDPOINTS = {
            "/api/v1/users",
            "/api/v1/auth/login",
            "/api/v1/auth/introspect",
            "/api/v1/auth/refresh-token",
            "/api/v1/auth/logout",
    };
    private final String[] PUBLIC_GET_ENDPOINTS = {
            "/api/v1/categories",
            "/api/v1/services/active",
            "/api/v1/products"
    };

    @Value("${signerKey}")
    private String signerKey;

    @Autowired
    private CustomJwtDecoder jwtDecoder;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // ✅ Sửa lại cách config
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                    // ✅ OPTIONS phải được permit TRƯỚC
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    // Cho phép POST vào các endpoint public
                    .requestMatchers(HttpMethod.POST, PUBLIC_POST_ENDPOINTS).permitAll()
                    // Cho phép GET không cần login
                    .requestMatchers(HttpMethod.GET, PUBLIC_GET_ENDPOINTS).permitAll()
                    // Các request khác đều cần JWT
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwtConfigurer -> jwtConfigurer
                            .decoder(jwtDecoder)
                            .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    )
                    .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
            );

    return httpSecurity.build();
}

@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    
    // ✅ Chỉ set 1 lần
    configuration.setAllowedOrigins(List.of("https://pet-shop-react-pearl.vercel.app"));
    
    // ✅ Phải có OPTIONS
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    
    // ✅ Cho phép tất cả headers
    configuration.setAllowedHeaders(List.of("*"));
    
    // ✅ Expose headers nếu frontend cần đọc
    configuration.setExposedHeaders(List.of("Authorization", "Content-Type"));
    
    // ✅ Set credentials
    configuration.setAllowCredentials(true);
    
    // ✅ Set maxAge để browser cache preflight response
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}


    // Custom converter để lấy authorities từ JWT
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);

        return jwtConverter;
    }



}
