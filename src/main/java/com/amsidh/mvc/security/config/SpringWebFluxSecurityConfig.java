package com.amsidh.mvc.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

import lombok.AllArgsConstructor;
import reactor.core.publisher.Mono;

//Spring Security Configuration
@EnableWebFluxSecurity
@AllArgsConstructor
public class SpringWebFluxSecurityConfig {

	private final AuthenticationManager authenticationManager;
	private final SecurityContextRepository securityContextRepository;

	@Bean
	public SecurityWebFilterChain getSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {

		// Default/inbuilt configuration. You add it or not. This will be present.
		// serverHttpSecurity.authorizeExchange().anyExchange().authenticated().and().httpBasic().and().formLogin();
		// Now customize the above security configuration

		// For
		// /demo/** no security
		// /employee/** GET method should have USER role
		// /test/** should have ROLE_ADMIN authority
		serverHttpSecurity.authorizeExchange(authorizeExchangeSpec -> {
			authorizeExchangeSpec.pathMatchers("/demo/**", "/signin/**", "/signup/**", "/webjars/**", "/v3/api-docs/**")
					.permitAll().pathMatchers(HttpMethod.GET, "/employee/**").hasRole("USER").pathMatchers("/test/**")
					.hasAuthority("ROLE_ADMIN").anyExchange().authenticated();
		}).exceptionHandling()
				.authenticationEntryPoint((response, exception) -> Mono
						.fromRunnable(() -> response.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
				.accessDeniedHandler((response, exception) -> Mono
						.fromRunnable(() -> response.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
				.and().formLogin().disable().httpBasic().disable().csrf().disable()
				.authenticationManager(authenticationManager).securityContextRepository(securityContextRepository)
				.requestCache().requestCache(NoOpServerRequestCache.getInstance());

		return serverHttpSecurity.build();
	}

}
