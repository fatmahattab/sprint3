package com.fatma.fruit.entities;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Saison {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idSai;
	private String nomSai;
	private String descriptionSai;
	@JsonIgnore
	@OneToMany(mappedBy = "saison")
	private List<Fruit> fruits;



}
