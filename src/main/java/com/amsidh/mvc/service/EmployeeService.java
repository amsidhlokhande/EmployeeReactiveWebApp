package com.amsidh.mvc.service;

import java.io.Serializable;

import com.amsidh.mvc.entity.Employee;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface EmployeeService extends Serializable {
	Mono<Employee> createEmployee(Employee employee);

	Mono<Employee> getEmployeeById(Integer id);

	Flux<Employee> getEmployees();

	Mono<Employee> updateEmployee(Integer id, Employee employee);

	Mono<Void> deleteEmployee(Integer id);

	Mono<Employee> getEmployeeByEmailId(String emailId);
}
