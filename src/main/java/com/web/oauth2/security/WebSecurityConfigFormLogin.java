package com.web.oauth2.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@Order(5)
public class WebSecurityConfigFormLogin extends WebSecurityConfigurerAdapter {

	@Autowired
	DataBaseAuthenticationProvider dbAuthenticationProvider;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off

		http
			.antMatcher("/admin*")
			.authorizeRequests()
			.anyRequest()
			.hasRole("ADMIN")
			.and()
		
			.formLogin()
			.loginPage("/")
			.loginProcessingUrl("/admin_login")
			.failureUrl("/#?error=loginError")
			.defaultSuccessUrl("/")
			
			.and().csrf().disable();
		// @formatter:on

	}

	/**
	 * <b>Description</b>
	 * <p>
	 * Custom authentication checking with database.
	 * </p>
	 * 
	 * @param auth
	 *            Authenciation buidler
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(dbAuthenticationProvider);
		auth.eraseCredentials(false);
	}

	
	
}