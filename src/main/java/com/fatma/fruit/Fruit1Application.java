package com.fatma.fruit;

import java.util.Date;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.service.FruitService;



@SpringBootApplication
public class Fruit1Application implements CommandLineRunner  {
	@Autowired
	FruitService fruitService;
	@Autowired
	private RepositoryRestConfiguration repositoryRestConfiguration;

	public static void main(String[] args) {
		SpringApplication.run(Fruit1Application.class, args);
	}
	
	@Override
	public void run(String... args) throws Exception {
	repositoryRestConfiguration.exposeIdsFor(Fruit.class);
	}

	//@Override
	//public void run(String... args) throws Exception {
		// TODO Auto-generated method stub
		//fruitService.saveFruit(new Fruit("Pomme", 2600.0, new Date()));
		//fruitService.saveFruit(new Fruit("banane", 2800.0, new Date()));
		//fruitService.saveFruit(new Fruit("fraise", 900.0, new Date()));
	//}
	
	

}
