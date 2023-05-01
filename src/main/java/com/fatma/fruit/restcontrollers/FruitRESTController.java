package com.fatma.fruit.restcontrollers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.service.FruitService;

@RestController
@RequestMapping("/api")
@CrossOrigin
public class FruitRESTController {
	@Autowired
	FruitService fruitService;
	@RequestMapping(method = RequestMethod.GET)
	public List<Fruit> getAllFruits() {
	return fruitService.getAllFruits();
	}
	
	@RequestMapping(value="/{id}",method = RequestMethod.GET)
	public Fruit getFruitById(@PathVariable("id") Long id) {
	return fruitService.getFruit(id);
	 }

	@RequestMapping(method = RequestMethod.POST)
	public Fruit createFruit(@RequestBody Fruit fruit) {
	return fruitService.saveFruit(fruit);
	}
	
	@RequestMapping(method = RequestMethod.PUT)
	public Fruit updateFruit(@RequestBody Fruit fruit) {
	return fruitService.updateFruit(fruit);
	}
	
	@RequestMapping(value="/{id}",method = RequestMethod.DELETE)
	public void deleteFruit(@PathVariable("id") Long id)
	{
	fruitService.deleteFruitById(id);
	}
	
	@RequestMapping(value="/fruitsai/{idSai}",method = RequestMethod.GET)
	public List<Fruit> getFruitsBySaiId(@PathVariable("idSai") Long idSai) {
	return fruitService.findBySaisonIdSai(idSai);
	}


}
