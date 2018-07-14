package com.web.oauth2.persistence;

import java.util.Arrays;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

@Service
@Profile("database-loader")
public class DatabaseLoader {

	@Autowired
	private UserRepository repository;

	@PostConstruct
	public void init() {
		if (repository.findByUserName("admin") == null) {
			User user = new User();
			user.setUserName("admin");
			user.setPassword("admin");
			user.setRoles(Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));
			repository.save(user);
		}
	}
}
