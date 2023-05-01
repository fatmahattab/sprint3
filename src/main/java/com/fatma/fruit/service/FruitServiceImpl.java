package com.fatma.fruit.service;

import java.util.List;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.entities.Saison;
import com.fatma.fruit.repos.FruitRepository;
import com.fatma.fruit.repos.SaisonRepository;

@Service
public class FruitServiceImpl implements FruitService{
	
	@Autowired
	FruitRepository fruitRepository;
	
	@Autowired
	SaisonRepository saisonRepository;

	@Override
	public Fruit saveFruit(Fruit f) {
		return fruitRepository.save(f);

	}

	@Override
	public Fruit updateFruit(Fruit f) {
		return fruitRepository.save(f);

	}

	@Override
	public void deleteFruit(Fruit f) {
		fruitRepository.delete(f);

	}

	@Override
	public void deleteFruitById(Long id) {
		// TODO Auto-generated method stub
		fruitRepository.deleteById(id);

	}

	@Override
	public Fruit getFruit(Long id) {
		return fruitRepository.findById(id).get();

	}

	@Override
	public List<Fruit> getAllFruits() {
		
		return fruitRepository.findAll();

	}

	@Override
	public Page<Fruit> getAllFruitsParPage(int page, int size) {
		return fruitRepository.findAll(PageRequest.of(page, size));

	}

	@Override
	public List<Fruit> findByNomFruit(String nom) {
		return fruitRepository.findByNomFruit(nom);
	}

	@Override
	public List<Fruit> findByNomFruitContains(String nom) {
		return fruitRepository.findByNomFruitContains(nom);
	}

	@Override
	public List<Fruit> findByNomPrix(String nom, Double prix) {
		return fruitRepository.findByNomPrix(nom, prix);
	}

	@Override
	public List<Fruit> findBySaison(Saison saison) {
		return fruitRepository.findBySaison(saison);
	}

	@Override
	public List<Fruit> findBySaisonIdSai(Long id) {
		return fruitRepository.findBySaisonIdSai(id);
	}

	@Override
	public List<Fruit> findByOrderByNomFruitAsc() {
		return fruitRepository.findByOrderByNomFruitAsc();
	}

	@Override
	public List<Fruit> trierFruitsNomsPrix() {
		return fruitRepository.trierFruitsNomsPrix();
	}

	@Override
	public List<Saison> getAllSaison() {
		return saisonRepository.findAll();
	}

}
