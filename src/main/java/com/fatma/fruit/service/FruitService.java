package com.fatma.fruit.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.entities.Saison;


public interface FruitService {
	Fruit saveFruit(Fruit f);
	Fruit updateFruit(Fruit f);
	void deleteFruit(Fruit f);
	 void deleteFruitById(Long id);
	Fruit getFruit(Long id);
	List<Fruit> getAllFruits();
	Page<Fruit> getAllFruitsParPage(int page, int size);
	List<Fruit> findByNomFruit(String nom);
	List<Fruit> findByNomFruitContains(String nom);
	List<Fruit> findByNomPrix (String nom, Double prix);
	List<Fruit> findBySaison (Saison saison);
	List<Fruit> findBySaisonIdSai(Long id);
	List<Fruit> findByOrderByNomFruitAsc();
	List<Fruit> trierFruitsNomsPrix();
	List<Saison> getAllSaison();
	



}
