package com.nightletter.global.security.token;

import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AccessToken {
	Integer memberId;
	GrantedAuthority role;
}
