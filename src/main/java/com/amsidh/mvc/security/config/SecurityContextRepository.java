package com.amsidh.mvc.security.config;

import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.AllArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@AllArgsConstructor
public class SecurityContextRepository implements ServerSecurityContextRepository {

	private final AuthenticationManager authenticationManager;

	@Override
	public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
		return Mono.empty();
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange exchange) {
		String bearer = "Bearer ";
		return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
				.filter(authHeader -> authHeader.startsWith(bearer))
				.map(subHeader -> subHeader.substring(bearer.length()))
				.flatMap(token -> Mono.just(new UsernamePasswordAuthenticationToken(token, token,
						Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"),
								new SimpleGrantedAuthority("ROLE_ADMIN")))))
				.flatMap(authentication -> authenticationManager.authenticate(authentication)
						.map(SecurityContextImpl::new));
	}

}