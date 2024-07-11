package com.nightletter.global.config;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.nightletter.global.security.handler.CurrentMemberArgumentResolver;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new CurrentMemberArgumentResolver());
	}
}
