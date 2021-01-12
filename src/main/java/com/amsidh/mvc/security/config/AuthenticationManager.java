package com.amsidh.mvc.security.config;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.amsidh.mvc.repository.EmployeeRepository;
import com.amsidh.mvc.util.JwtUtil;

import lombok.AllArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@AllArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

	private JwtUtil jwtUtil;
	private EmployeeRepository employeeRepository;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {

		String token = authentication.getCredentials().toString();
		String username = jwtUtil.getUsernameFromToken(token);

		return employeeRepository.findByEmailId(username).flatMap(employee -> {
			if (employee.getEmailId().equals(username) && jwtUtil.isTokenValidated(token)) {
				return Mono.just(authentication);
			} else {
				return Mono.empty();
			}
		}).switchIfEmpty(Mono.empty());
	}

}