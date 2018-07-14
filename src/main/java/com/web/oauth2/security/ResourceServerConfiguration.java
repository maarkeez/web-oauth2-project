package com.web.oauth2.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
/* Declaring that the app is a Resource Server */
@EnableResourceServer
class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	/**
	 * To protect the path "/me" with the access token.
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
	}
}
