package com.web.oauth2.security;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

@Configuration
/* To enable oauth client features as loggin with facebook or github */
@EnableOAuth2Client

/* To allows this application create all the endpoints needed for serve as oauth2-Server */
@EnableAuthorizationServer

@Import(value = { ResourceServerTokenServicesConfiguration.class })

/* Set "ResourceServerConfiguration" class filter preference over this one */
@Order(6)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			/* All requests are protected by default */
			.antMatcher("/**").authorizeRequests()
			
			/* Explicitly excluded */
			.antMatchers("/", "/login**", "/webjars/**", "/error**").permitAll()
			
			/* All other end-points require an authenticated user */
			.anyRequest().authenticated().and()
			
			/* Unauthenticated users are re-directed to the home page */
			.exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and()
		      
			.logout().logoutSuccessUrl("/").permitAll()
			
			/* CRSF Token for session */ 
		    .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		    
		 
		    
		    /* Authentication filter */
		    .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
		    
		    
		    ;
		
		// @formatter:on;
	}

	/**
	 * Handler for explicitly support the redirects from this application to Facebook/GitHub
	 * 
	 * @return
	 */
	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(github(), "/login/github"));
//		filters.add(ssoFilter(twitter(), "/login/twitter"));
		filters.add(ssoFilter(linkedin(), "/login/linkedin"));
		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);

		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);

		UserInfoTokenServices tokenService = new UserInfoTokenServices(client.getResource().getUserInfoUri(), client.getClient().getClientId());
		PrincipalExtractorBuilder extractorBuilder = new PrincipalExtractorBuilder();
		tokenService.setPrincipalExtractor(extractorBuilder.build(client.getResource().getId()));

		filter.setTokenServices(tokenService);
		return filter;
	}

	/**
	 * Wires the filter up so that it gets called in the right order in this Spring Boot application
	 * 
	 * @param filter
	 * @return
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		// low order that it comes before the main Spring Security filter.
		// In this way we can use it to handle redirects signaled by expceptions in authentication requests.
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}
	
//	@Bean
//	@ConfigurationProperties("twitter")
//	public ClientResources twitter() {
//		return new ClientResources();
//	}
	
	@Bean
	@ConfigurationProperties("linkedin")
	public ClientResources linkedin() {
		return new ClientResources();
	}
}