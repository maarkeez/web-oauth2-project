package com.web.oauth2.security;

import java.util.Calendar;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.web.oauth2.persistence.User;
import com.web.oauth2.persistence.UserRepository;

/**
 * <b>Description</b>
 * <p>
 * Allows authorize and authenticate user through database.
 * </p>
 * 
 */
@Component
public class DataBaseAuthenticationProvider implements AuthenticationProvider {

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private UserRepository userRepository;

	/**
	 * <b>Description</b>
	 * <p>
	 * Checks if user exists on database, and if it is the same password
	 * </p>
	 * <p>
	 * If user is correct authenticated, sets session roles.
	 * </p>
	 * 
	 * @param authentication
	 *            User authentication retrieved from the Http Login Request.
	 * @return User session authentication with roles.
	 * @throws BadCredentialsException
	 *             <code>AuthenticationException</code> when:<br>
	 *             (1) Wrong credentials <br/>
	 *             (2) User does not exist.
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		// Retrieve user/credentials for the HttpRequest
		String userName = authentication.getName().trim();
		String password = (String) authentication.getCredentials();

		// Check password
		if (password == null || password.isEmpty()) {
			log.debug("Empty password for user: " + userName);
			throw new BadCredentialsException("Could not retrieve user for given username/credentials");
		}

		// Retrieve user from database
		User user = userRepository.findByUserName(userName);

		// Check user exists.
		if (user == null || !user.getPassword().equals(password)) {
			log.debug("User " + userName + " is not registered or wrong credentials");
			throw new BadCredentialsException("Could not retrieve user for given username/credentials");
		}

		// Update last access date
		user.setLastAccess(Calendar.getInstance().getTime());
		userRepository.save(user);

		// Retrieve role list
		List<GrantedAuthority> roles = user.getRoles();

		// Create authentication token for logged user
		return new UsernamePasswordAuthenticationToken(user, password, roles);
	}

	/**
	 * <b>Description</b>
	 * <p>
	 * Returns true if this AuthenticationProvider supports the indicated Authentication object.
	 * </p>
	 * <p>
	 * Returning true does not guarantee an AuthenticationProvider will be able to authenticate the presented instance of the Authentication class. It simply indicates it can support closer evaluation of it. An AuthenticationProvider can still return
	 * null from the authenticate(Authentication) method to indicate another AuthenticationProvider should be tried.
	 * 
	 * Selection of an AuthenticationProvider capable of performing authentication is conducted at runtime the ProviderManager.
	 * </p>
	 * 
	 * @param arg0
	 *            authentication
	 * @return true
	 */
	@Override
	public boolean supports(Class<?> arg0) {
		return true;
	}

}
