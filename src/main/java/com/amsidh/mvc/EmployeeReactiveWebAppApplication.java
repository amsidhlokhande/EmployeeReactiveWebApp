package com.amsidh.mvc;

import java.io.Serializable;
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
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
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
@Slf4j
class EmployeeHandler {

	private final EmployeeService employeeService;

	public EmployeeHandler(EmployeeService employeeService) {
		log.info("Loading EmployeeHandler!!!");
		log.info("EmployeeService employeeService " + employeeService);
		this.employeeService = employeeService;
	}

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

}

@Repository
interface EmployeeRepository extends ReactiveMongoRepository<Employee, Integer>, Serializable {

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

}

interface EmployeeService extends Serializable {
	Mono<Employee> createEmployee(Employee employee);

	Mono<Employee> getEmployeeById(Integer id);

	Flux<Employee> getEmployees();

	Mono<Employee> updateEmployee(Integer id, Employee employee);

	Mono<Void> deleteEmployee(Integer id);
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
			return employeeRepository.save(emp);
		});
	}

	@Override
	public Mono<Void> deleteEmployee(Integer id) {
		log.info("EmployeeServiceImpl deleteEmployee method called");
		return this.employeeRepository.deleteById(id);
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
class SpringWebFluxSecurityConfig {

	@Bean
	public SecurityWebFilterChain getSecurityFilterChain(ServerHttpSecurity serverHttpSecurity) {

		// Default/inbuilt configuration. You add it or not. This will be present.
		// serverHttpSecurity.authorizeExchange().anyExchange().authenticated().and().httpBasic().and().formLogin();
		// Now customize the above security configuration

		// For
		// /demo/** no security
		// /employee/** GET method should have USER role
		// /test/** should have ROLE_ADMIN authority
		serverHttpSecurity.authorizeExchange().pathMatchers("/demo/**").permitAll()
				.pathMatchers(HttpMethod.GET, "/employee/**").hasRole("USER").pathMatchers("/test/**")
				.hasAuthority("ROLE_ADMIN").anyExchange().authenticated().and().formLogin().and().httpBasic();
        serverHttpSecurity.csrf().disable();
		return serverHttpSecurity.build();
	}

	@Bean
	public MapReactiveUserDetailsService getUserDetailsService() {

		UserDetails user1 = User.withDefaultPasswordEncoder().username("amsidh").password("amsidh").roles("USER")
				.build();    //Only USER Role
		UserDetails user2 = User.withDefaultPasswordEncoder().username("adithi").password("adithi")
				.roles("USER", "ADMIN").build();  // Both USER and ADMIN Role
		
		UserDetails user3 = User.withDefaultPasswordEncoder().username("adity").password("adity")
				.roles("ADMIN").build(); //only ADMIN role. But whoever have ADMIN role he also get USER roles by default

		return new MapReactiveUserDetailsService(user1, user2, user3);
	}
}