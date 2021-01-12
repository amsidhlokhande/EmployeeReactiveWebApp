package com.amsidh.mvc.repository;

import java.io.Serializable;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import com.amsidh.mvc.entity.Employee;

import reactor.core.publisher.Mono;

@Repository
public interface EmployeeRepository extends ReactiveMongoRepository<Employee, Integer>, Serializable {
	Mono<Employee> findByEmailId(String emailId);
}
