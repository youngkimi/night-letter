package com.nightletter.global.security.handler.jwt;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nightletter.global.exception.CommonErrorCode;
import com.nightletter.global.exception.ValidationException;
import com.nightletter.global.security.token.AccessToken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtProvider jwtProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		try {

			// check baseUrl for Prometheus monitoring
			// if (request.getRequestURI().startsWith("/system")) {
			// 	filterChain.doFilter(request, response);
			// 	return;
			// }

			// 토큰 확인.
			String token = parseBearerToken(request);

			if (token == null) {
				filterChain.doFilter(request, response);
				return;
			}

			AccessToken accessToken = jwtProvider.validate(token);

			SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

			// TODO Authentication memberId Integer, Use Annotation

			AbstractAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(accessToken.getMemberId().toString(), null, List.of(accessToken.getRole()));

			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			securityContext.setAuthentication(authenticationToken);
			SecurityContextHolder.setContext(securityContext);

		} catch (Exception e) {
			log.info("ERROR OCCURED IN PARSING TOKEN");
			e.printStackTrace();
		}

		filterChain.doFilter(request, response);
	}

	private String parseBearerToken(HttpServletRequest request) {

		Cookie[] cookies = request.getCookies();

	   	String accessToken = null;

	    if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("access-token")) {
					accessToken = cookie.getValue();
				}
			}
		}

		if (accessToken == null && request.getRequestURI().startsWith("/system")) {
			String authToken = request.getHeader(HttpHeaders.AUTHORIZATION);

			if (authToken != null && authToken.startsWith("Bearer ")) {
				accessToken = authToken.substring("Bearer ".length());
			}
		}

		if (accessToken == null) {
			throw new ValidationException(CommonErrorCode.INVALID_AUTHORIZATION, "NOT A VALID TOKEN");
		}

		return accessToken;
	}

}
