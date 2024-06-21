package com.nightletter.global.security.handler.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.nightletter.global.security.token.AccessToken;
import com.nightletter.global.utils.times.DateTimeUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtProvider {
	@Value("${jwt.secret-key}")
	private String secretKey;

	public String create(String memberId) {

		Date expiredDate = Date.from(DateTimeUtils.tokenExpireTime());

		System.out.println("CREATE EXPIRED TIME: " + expiredDate);

		Key key = Keys.hmacShaKeyFor(secretKey.getBytes((StandardCharsets.UTF_8)));

		Map<String, Object> roles = Map.of("role", List.of("ROLE_MEMBER"));

		return Jwts.builder()
			.signWith(key, SignatureAlgorithm.HS256)
			.setSubject(memberId)
			.setIssuedAt(new Date())
			.setExpiration(expiredDate)
			.addClaims(roles)
			.compact();
	}

	// public String validate(String jwt) {
	//
	// 	String subject = null;
	// 	Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	//
	// 	try {
	// 		subject = Jwts.parserBuilder()
	// 			.setSigningKey(key)
	// 			.build()
	// 			.parseClaimsJws(jwt)
	// 			.getBody()
	// 			.getSubject();
	//
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 		return null;
	// 	}
	//
	// 	System.out.println(subject);
	//
	// 	return subject;
	// }

	public AccessToken validate(String jwt) {

		String subject = null;
		Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

		try {
			Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(jwt)
				.getBody();

			subject = claims.getSubject();
			Object parsedRoles = claims.get("role");

			List<GrantedAuthority> convertedRoles = null;

			if (parsedRoles instanceof List<?> roles) {

				if (! roles.stream()
					.allMatch(role -> role instanceof String)) {
					return null;
				}

				convertedRoles = roles.stream()
					.map(role -> new SimpleGrantedAuthority(role.toString()))
					.collect(Collectors.toList());
			}

			return AccessToken.builder()
				.memberId(Integer.parseInt(subject))
				.roles(convertedRoles)
				.build();

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}
}
