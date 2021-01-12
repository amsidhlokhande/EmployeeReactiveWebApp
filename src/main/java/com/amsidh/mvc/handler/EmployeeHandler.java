package com.amsidh.mvc.handler;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.amsidh.mvc.entity.Employee;
import com.amsidh.mvc.model.LoginRequestModel;
import com.amsidh.mvc.model.LoginResponseModel;
import com.amsidh.mvc.service.EmployeeService;
import com.amsidh.mvc.util.JwtUtil;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@AllArgsConstructor
@Slf4j
public class EmployeeHandler {

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

		return loginRequestModelMono.flatMap(loginRequestModel -> employeeService
				.getEmployeeByEmailId(loginRequestModel.getUsername()).flatMap(employee -> {
					if (employee.getPassword().equals(loginRequestModel.getPassword())) {
						return ServerResponse.ok()
								.bodyValue(new LoginResponseModel(jwtUtil.generateToken(loginRequestModel)));
					} else {
						return ServerResponse.badRequest().build();
					}
				}).switchIfEmpty(ServerResponse.badRequest().build()));
	}
}
