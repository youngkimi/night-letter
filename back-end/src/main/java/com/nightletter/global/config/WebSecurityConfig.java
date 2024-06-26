package com.nightletter.global.config;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nightletter.global.security.handler.OAuth2SuccessHandler;
import com.nightletter.global.security.handler.jwt.JwtAuthenticationFilter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configurable
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final DefaultOAuth2UserService oAuth2UserService;
	private final OAuth2SuccessHandler oAuth2SuccessHandler;

	@Bean
	protected SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {

		httpSecurity
			.cors(cors -> cors
				.configurationSource(corsConfigurationSource())
			)
			.csrf(CsrfConfigurer::disable)
			.httpBasic(HttpBasicConfigurer::disable)
			.sessionManagement(sessionManagement -> sessionManagement
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			.authorizeHttpRequests(request -> request
				// TODO 수정 필요.
				.requestMatchers("/api/v2/auth/**", "/oauth2/**").permitAll()
				.requestMatchers("/api/v2/**").hasAnyRole("MEMBER", "ADMIN")
				.requestMatchers("/system/**").hasRole("ADMIN")
				.anyRequest().authenticated()
			)
			.oauth2Login(oauth2 -> oauth2
				.authorizationEndpoint(endPoint -> endPoint.baseUri("/api/v2/auth/oauth2"))
				.redirectionEndpoint(endPoint -> endPoint.baseUri("/oauth2/callback/**"))
				.userInfoEndpoint(endPoint -> endPoint.userService(oAuth2UserService))
				.successHandler(oAuth2SuccessHandler)
			)
			.exceptionHandling(exceptionHandling -> exceptionHandling
				.authenticationEntryPoint(new FailedAuthenticationEntryPoint())
			)
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


		return httpSecurity.build();
	}

	@Bean
	protected CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration corsConfiguration = new CorsConfiguration();

		corsConfiguration.setAllowedOrigins(
			List.of(
				"http://letter-for.me",
				"https://letter-for.me",
				"http://dev.letter-for.me",
				"https://dev.letter-for.me",
				"http://localhost:3000",
				"https://localhost:3001"
			)
		);

		corsConfiguration.setAllowedMethods(
			List.of("GET", "DELETE", "PUT", "PATCH", "POST", "OPTIONS")
		);

		corsConfiguration.addAllowedHeader("*");
		corsConfiguration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

		source.registerCorsConfiguration("/**", corsConfiguration);

		return source;
	}

	private static class FailedAuthenticationEntryPoint implements AuthenticationEntryPoint {

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
			response.setContentType("application/json");
			// 권한 없음.
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			// {"code": "NP", "message": "No Permission."}
			response.getWriter().write("{\"code\": \"NP\", \"message\": \"No Permission.\"}");
		}
	}
}
