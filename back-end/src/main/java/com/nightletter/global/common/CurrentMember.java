package com.nightletter.global.common;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

// getMember by expression
@AuthenticationPrincipal(expression = "member")
public @interface CurrentMember {
}
