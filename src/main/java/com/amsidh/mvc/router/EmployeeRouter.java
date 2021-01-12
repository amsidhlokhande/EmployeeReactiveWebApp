package com.amsidh.mvc.router;

import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.amsidh.mvc.entity.Employee;
import com.amsidh.mvc.handler.EmployeeHandler;
import com.amsidh.mvc.service.EmployeeService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
public class EmployeeRouter {

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
		return RouterFunctions
				.route(RequestPredicates.POST("/signin").and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
						.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), employeeHandler::signIn)
				.and(RouterFunctions.route(
						RequestPredicates.POST("/signup").and(RequestPredicates.contentType(MediaType.APPLICATION_JSON))
								.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						employeeHandler::createEmployee));
	}

}