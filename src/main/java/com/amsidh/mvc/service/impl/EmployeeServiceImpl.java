package com.amsidh.mvc.service.impl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.amsidh.mvc.entity.Employee;
import com.amsidh.mvc.repository.EmployeeRepository;
import com.amsidh.mvc.service.EmployeeService;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class EmployeeServiceImpl implements EmployeeService {
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
