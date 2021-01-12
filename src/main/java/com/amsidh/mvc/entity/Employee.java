package com.amsidh.mvc.entity;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Document("employees")
public class Employee implements Serializable {
	private static final long serialVersionUID = 2401291741647022968L;

	@Id
	private Integer id;
	private String name;
	private Double salary;
	private String emailId; // acts as username
	private String password;

}

