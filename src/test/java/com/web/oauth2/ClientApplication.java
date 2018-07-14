package com.web.oauth2;

import java.security.Principal;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableAutoConfiguration
@Configuration
@EnableOAuth2Sso
@RestController
public class ClientApplication {

	@RequestMapping("/")
	public String home(Principal user) {
		return "Hello " + user.getName();
	}

	public static void main(String[] args) {
		new SpringApplicationBuilder(ClientApplication.class).properties("spring.config.name=client").run(args);
	}

}
