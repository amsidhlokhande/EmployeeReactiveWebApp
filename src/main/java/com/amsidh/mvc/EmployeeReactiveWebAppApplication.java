package com.amsidh.mvc;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springdoc.core.GroupedOpenApi;
import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.WebProperties.Resources;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.data.mongodb.repository.config.EnableReactiveMongoRepositories;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@SpringBootApplication
@EnableReactiveMongoRepositories(basePackageClasses = { EmployeeRepository.class })
public class EmployeeReactiveWebAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(EmployeeReactiveWebAppApplication.class, args);
	}

	@Bean
	public GroupedOpenApi employeesOpenApi() {
		String[] paths = { "/employees/**" };
		return GroupedOpenApi.builder().group("employees").pathsToMatch(paths).build();
	}

}

@Component
@AllArgsConstructor
@Slf4j
class EmployeeHandler {

	private final EmployeeService employeeService;
	private final JwtUtil jwtUtil;

	public Mono<ServerResponse> createEmployee(ServerRequest serverRequest) {
		log.info("Inside EmployeeHandler createEmployee method");
		return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(
				serverRequest.bodyToMono(Employee.class).flatMap(employeeService::createEmployee), Employee.class);
	}

	public Mono<ServerResponse> getEmployees(ServerRequest serverRequest) {
		log.info("Inside EmployeeHandler getEmployees method");
		return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(employeeService.getEmployees(),
				Employee.class);
	}

	public Mono<ServerResponse> getEmployeeById(ServerRequest serverRequest) {
		log.info("Inside EmployeeHandler getEmployeeById method");
		return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(
				employeeService.getEmployeeById(Integer.parseInt(serverRequest.pathVariable("id"))), Employee.class);
	}

	public Mono<ServerResponse> updateEmployeeById(ServerRequest serverRequest) {
		log.info("Inside EmployeeHandler updateEmployeeById method");
		Mono<Employee> updatedEmployee = serverRequest.bodyToMono(Employee.class).flatMap(employee -> employeeService
				.updateEmployee(Integer.parseInt(serverRequest.pathVariable("id")), employee));
		return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(updatedEmployee, Employee.class);
	}

	public Mono<ServerResponse> deleteEmployeeById(ServerRequest serverRequest) {
		log.info("Inside EmployeeHandler deleteEmployeeById method");
		return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
				.body(employeeService.deleteEmployee(Integer.parseInt(serverRequest.pathVariable("id"))), Void.class);

	}

	public Mono<ServerResponse> getError(ServerRequest serverRequest) {
		return ServerResponse.badRequest().bodyValue(new RuntimeException("My won runtime exception"));
	}

	public Mono<ServerResponse> signIn(ServerRequest serverRequest) {
		Mono<LoginRequestModel> loginRequestModelMono = serverRequest.bodyToMono(LoginRequestModel.class);

		return loginRequestModelMono.flatMap(loginRequestModel -> employeeService.getEmployeeByEmailId(loginRequestModel.getUsername())
				.flatMap(employee -> {
					if (employee.getPassword().equals(loginRequestModel.getPassword())) {
						return ServerResponse.ok().bodyValue(new LoginResponseModel(jwtUtil.generateToken(loginRequestModel)));
					} else {
						return ServerResponse.badRequest().build();
					}
				}).switchIfEmpty(ServerResponse.badRequest().build()));
	}
}

@Data
@AllArgsConstructor
class LoginResponseModel{
	private String jwtToken;
}

@Data
@AllArgsConstructor
class LoginRequestModel {
	private String username;
	private String password;
}

@Configuration
@Slf4j
class EmployeeRouter {

	private static final String EMPLOYEES_BASE_URI = "/employees";
	private static final String EMPLOYEES_BASE_URI_WITH_ID = EMPLOYEES_BASE_URI + "/{id}";

	@RouterOperations({
			@RouterOperation(path = EMPLOYEES_BASE_URI, method = RequestMethod.GET, beanClass = EmployeeService.class, beanMethod = "getEmployees", operation = @Operation(operationId = "getAllEmployee", tags = "GetAllEmployee")),

			@RouterOperation(path = EMPLOYEES_BASE_URI_WITH_ID, method = RequestMethod.GET, beanClass = EmployeeService.class, beanMethod = "getEmployeeById", operation = @Operation(operationId = "findEmployeeById", summary = "Find purchase order by ID", tags = {
					"GetEmployee" }, parameters = {
							@Parameter(in = ParameterIn.PATH, name = "id", description = "Employee Id") }, responses = {
									@ApiResponse(responseCode = "200", description = "successful operation", content = @Content(schema = @Schema(implementation = Employee.class))),
									@ApiResponse(responseCode = "400", description = "Invalid Employee ID supplied"),
									@ApiResponse(responseCode = "404", description = "Employee not found") })),

			@RouterOperation(path = EMPLOYEES_BASE_URI, method = RequestMethod.POST, beanClass = EmployeeService.class, beanMethod = "createEmployee", operation = @Operation(operationId = "postEmployee", tags = "PostEmployee", requestBody = @RequestBody(required = true, content = @Content(schema = @Schema(implementation = Employee.class))))),

			@RouterOperation(path = EMPLOYEES_BASE_URI_WITH_ID, method = RequestMethod.PATCH, beanClass = EmployeeService.class, beanMethod = "updateEmployee", operation = @Operation(operationId = "updateEmployee", summary = "Find employee by ID", tags = {
					"PatchEmployee" }, parameters = {
							@Parameter(in = ParameterIn.PATH, name = "id", description = "Employee Id") }, requestBody = @RequestBody(required = true, content = @Content(schema = @Schema(implementation = Employee.class))),

					responses = {
							@ApiResponse(responseCode = "200", description = "successful operation", content = @Content(schema = @Schema(implementation = Employee.class))),
							@ApiResponse(responseCode = "400", description = "Invalid Employee ID supplied"),
							@ApiResponse(responseCode = "404", description = "Employee not found") })),
			@RouterOperation(path = EMPLOYEES_BASE_URI_WITH_ID, method = RequestMethod.DELETE, beanClass = EmployeeService.class, beanMethod = "deleteEmployee", operation = @Operation(operationId = "deleteEmployee", tags = "DeleteEmployee", parameters = @Parameter(in = ParameterIn.PATH, name = "id", description = "Employee Id"))) })
	@Bean
	public RouterFunction<ServerResponse> getEmployeeRouters(EmployeeHandler employeeHandler) {
		log.info("EmployeeRouter getEmployeeRouters called");
		return RouterFunctions
				.route(RequestPredicates.GET(EMPLOYEES_BASE_URI)
						.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), employeeHandler::getEmployees)

				.and(RouterFunctions.route(
						RequestPredicates.GET(EMPLOYEES_BASE_URI_WITH_ID)
								.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::getEmployeeById))

				.and(RouterFunctions.route(
						RequestPredicates.POST(EMPLOYEES_BASE_URI)
								.and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
								.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::createEmployee))
				.and(RouterFunctions.route(
						RequestPredicates.PATCH(EMPLOYEES_BASE_URI_WITH_ID)
								.and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
								.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::updateEmployeeById))
				.and(RouterFunctions.route(
						RequestPredicates.DELETE(EMPLOYEES_BASE_URI_WITH_ID)
								.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::deleteEmployeeById));
	}

	@Bean
	public RouterFunction<ServerResponse> getErrorRoutes(EmployeeHandler employeeHandler) {
		return RouterFunctions.route(RequestPredicates.GET("/emp/error"), employeeHandler::getError);
	}

	@Bean
	public RouterFunction<ServerResponse> routes1(EmployeeHandler employeeHandler) {
		return RouterFunctions
				.route(RequestPredicates.GET("/test").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::getEmployees)
				.and(RouterFunctions.route(
						RequestPredicates.GET("/test/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::getEmployeeById));
	}

	@Bean
	public RouterFunction<ServerResponse> routes2(EmployeeHandler employeeHandler) {
		return RouterFunctions
				.route(RequestPredicates.GET("/demo").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::getEmployees)
				.and(RouterFunctions.route(
						RequestPredicates.GET("/demo/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::getEmployeeById));
	}

	@Bean
	public RouterFunction<ServerResponse> signInAndSignUpRoutes(EmployeeHandler employeeHandler) {
		return RouterFunctions.route(RequestPredicates.POST("/signin")
					                                  .and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
					                                  .and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), employeeHandler::signIn)
				              .and(RouterFunctions.route(RequestPredicates.POST("/signup")
										                                    .and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
										                                    .and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), employeeHandler::createEmployee));
	}

}

@Repository
interface EmployeeRepository extends ReactiveMongoRepository<Employee, Integer>, Serializable {
	Mono<Employee> findByEmailId(String emailId);
}

@Data
@AllArgsConstructor
@NoArgsConstructor
@Document("employees")
class Employee implements Serializable {
	private static final long serialVersionUID = 2401291741647022968L;

	@Id
	private Integer id;
	private String name;
	private Double salary;
	private String emailId; // acts as username
	private String password;

}

interface EmployeeService extends Serializable {
	Mono<Employee> createEmployee(Employee employee);

	Mono<Employee> getEmployeeById(Integer id);

	Flux<Employee> getEmployees();

	Mono<Employee> updateEmployee(Integer id, Employee employee);

	Mono<Void> deleteEmployee(Integer id);

	Mono<Employee> getEmployeeByEmailId(String emailId);
}

@Service
@Slf4j
class EmployeeServiceImpl implements EmployeeService {
	private static final long serialVersionUID = -7618796759117210654L;

	private final EmployeeRepository employeeRepository;

	public EmployeeServiceImpl(EmployeeRepository employeeRepository) {
		log.info("Loading EmployeeServiceImpl");
		this.employeeRepository = employeeRepository;
		log.info("EmployeeRepository employeeRepository " + employeeRepository);
	}

	@Override
	public Mono<Employee> createEmployee(Employee employee) {
		log.info("EmployeeServiceImpl createEmployee method called");
		return this.employeeRepository.save(employee);
	}

	@Override
	public Mono<Employee> getEmployeeById(Integer id) {
		log.info("EmployeeServiceImpl getEmployeeById method called");

		return this.employeeRepository.findById(id);
	}

	@Override
	public Flux<Employee> getEmployees() {
		log.info("EmployeeServiceImpl getEmployees method called");

		return this.employeeRepository.findAll();
	}

	@Override
	public Mono<Employee> updateEmployee(Integer id, Employee employee) {
		log.info("EmployeeServiceImpl updateEmployee method called");
		Mono<Employee> findById = this.employeeRepository.findById(id);
		return findById.flatMap(emp -> {
			Optional.ofNullable(employee.getName()).ifPresent(emp::setName);
			Optional.ofNullable(employee.getSalary()).ifPresent(emp::setSalary);
			Optional.ofNullable(employee.getEmailId()).ifPresent(emp::setEmailId);
			Optional.ofNullable(employee.getPassword()).ifPresent(emp::setPassword);
			return employeeRepository.save(emp);
		});
	}

	@Override
	public Mono<Void> deleteEmployee(Integer id) {
		log.info("EmployeeServiceImpl deleteEmployee method called");
		return this.employeeRepository.deleteById(id);
	}

	@Override
	public Mono<Employee> getEmployeeByEmailId(String emailId) {
		log.info("EmployeeServiceImpl getEmployeeByEmailId method called");
		return this.employeeRepository.findByEmailId(emailId);
	}

}

/*
 * For Customize error handling we need to implement the
 * AbstractErrorWebExceptionHandler
 */

@Component
class MyErrorHander extends AbstractErrorWebExceptionHandler {

	public MyErrorHander(ErrorAttributes errorAttributes, Resources resources, ApplicationContext applicationContext,
			ServerCodecConfigurer serverCodecConfigurer) {
		super(errorAttributes, resources, applicationContext);
		super.setMessageReaders(serverCodecConfigurer.getReaders());
		super.setMessageWriters(serverCodecConfigurer.getWriters());
	}

	@Override
	protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
		return RouterFunctions.route(RequestPredicates.all(), this::errorHandler);
	}

	public Mono<ServerResponse> errorHandler(ServerRequest serverRequest) {
		Map<String, Object> errorAttributes = this.getErrorAttributes(serverRequest, false);
		return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR).body(BodyInserters.fromValue(errorAttributes));
	}
}

//Spring Security Configuration
@EnableWebFluxSecurity
@AllArgsConstructor
class SpringWebFluxSecurityConfig {

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
			authorizeExchangeSpec.pathMatchers("/demo/**", "/signin/**", "/signup/**").permitAll()
					.pathMatchers(HttpMethod.GET, "/employee/**").hasRole("USER").pathMatchers("/test/**")
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

@Component
class JwtUtil {

	private String secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private String expireTimeInMillSec = "300000";

	public String generateToken(LoginRequestModel loginRequestModel) {

		Date now = new Date();
		Map<String, Object> claims = new HashMap<>();
		claims.put("alg", "HS256");
		claims.put("typ", "JWT");

		return Jwts.builder().setHeaderParams(claims).setSubject(loginRequestModel.getUsername())
				.signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
				.setIssuedAt(now).setExpiration(new Date(now.getTime() + Long.parseLong(expireTimeInMillSec)))
				.compact();
	}

	public Claims getClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes())).parseClaimsJws(token)
				.getBody();
	}

	public String getUsernameFromToken(String token) {
		return getClaimsFromToken(token).getSubject();
	}

	public Date getExpirationDate(String token) {
		return getClaimsFromToken(token).getExpiration();
	}

	public Boolean isTokenExpired(String token) {
		return getExpirationDate(token).before(new Date());
	}

	public Boolean isTokenValidated(String token) {
		return !isTokenExpired(token);
	}

}

@Component
@AllArgsConstructor
class AuthenticationManager implements ReactiveAuthenticationManager {

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

@Component
@AllArgsConstructor
class SecurityContextRepository implements ServerSecurityContextRepository {

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