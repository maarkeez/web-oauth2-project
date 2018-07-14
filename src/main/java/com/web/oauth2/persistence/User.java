package com.web.oauth2.persistence;

import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;

@Entity
@Table
public class User {

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Integer id;

	@Column(nullable = false, unique = true)
	private String userName;
	@Column(nullable = false)
	private String password;

	@ElementCollection(fetch = FetchType.EAGER)
	private List<GrantedAuthority> roles;

	private Date lastAccess;

	public User() {
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public List<GrantedAuthority> getRoles() {
		return roles;
	}

	public void setRoles(List<GrantedAuthority> roles) {
		this.roles = roles;
	}

	public Date getLastAccess() {
		return lastAccess;
	}

	public void setLastAccess(Date lastAccess) {
		this.lastAccess = lastAccess;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
