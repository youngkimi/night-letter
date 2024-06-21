package com.nightletter.global.security.token;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AccessToken {
	Integer memberId;
	List<GrantedAuthority> roles;
}
