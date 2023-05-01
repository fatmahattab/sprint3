package com.fatma.fruit.entities;

import java.util.Date;

import org.springframework.format.annotation.DateTimeFormat;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;

@Entity
public class Fruit {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)

	private Long idFruit;
	
	@NotNull
	@Size (min = 4,max = 15)
	private String nomFruit;
	
	@Min(value = 10)
	 @Max(value = 10000)
	private Double prixFruit;
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@PastOrPresent
	private Date dateDebSaison;
	@ManyToOne
	private Saison saison;
	public Saison getSaison() {
		return saison;
	}
	public void setSaison(Saison saison) {
		this.saison = saison;
	}
	public Fruit() {
	super();
	}
	public Fruit(String nomFruit, Double prixFruit, Date dateDebSaison) {
	super();
	this.nomFruit = nomFruit;
	this.prixFruit = prixFruit;
	this.dateDebSaison = dateDebSaison;
	}
	public Long getIdFruit() {
	return idFruit;
	}
	public void setIdFruit(Long idFruit) {
	this.idFruit = idFruit;
	}
	public String getNomFruit() {
	return nomFruit;
	}
	public void setNomFruit(String nomFruit) {
	this.nomFruit = nomFruit;
	}
	public Double getPrixFruit() {
	return prixFruit;
	}
	public void setPrixFruit(Double prixFruit) {
	this.prixFruit = prixFruit;
	}
	public Date getDateDebSaison() {
	return dateDebSaison;
	}
	public void setDateDebSaison(Date dateDebSaison) {
	this.dateDebSaison = dateDebSaison;
	}
	@Override
	public String toString() {
	return "Fruit [idFruit=" + idFruit + ", nomProduit=" +
	nomFruit + ", prixFruit=" + prixFruit
	+ ", dateCreation=" + dateDebSaison + "]";
	}
	}




