package com.fatma.fruit;

import java.util.Date;



import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.entities.Saison;
import com.fatma.fruit.repos.FruitRepository;
import com.fatma.fruit.service.FruitService;


@SpringBootTest
class FruitApplicationTests {

	
	@Autowired
	private FruitRepository fruitRepository;
	@Autowired
	private FruitService fruitService;
	@Test
	public void testCreateFruit() {
	Fruit frui = new Fruit("pomme",3200.500,new Date());
	fruitRepository.save(frui);
	}
	
	@Test
	public void testFindFruit()
	{
	Fruit f = fruitRepository.findById(1L).get(); 
	System.out.println(f);
	}
	@Test
	public void testUpdateFruit()
	{
	Fruit f = fruitRepository.findById(1L).get();
	f.setPrixFruit(1000.0);
	fruitRepository.save(f);
	}
	

	@Test
	public void testDeleteFruit()
	{
		fruitRepository.deleteById(1L);;
	}
	 
	@Test
	public void testListerTousProduits()
	{
	List<Fruit> fruits = fruitRepository.findAll();
	for (Fruit f : fruits)
	{
	System.out.println(f);
	}
	

	}
	
	@Test
	 public void testFindByNomFruitContains()
	 {
	 Page<Fruit> prods = fruitService.getAllFruitsParPage(0,2);
	 System.out.println(prods.getSize());
	 System.out.println(prods.getTotalElements());
	
	 System.out.println(prods.getTotalPages());
	 prods.getContent().forEach(p -> {System.out.println(p.toString());
	  });
	 /*ou bien
	 for (Produit p : prods)
	 {
	 System.out.println(p);
	 } */
	 }
	
	@Test
	public void testFindFruitByNom()
	{
	List<Fruit> frui = fruitRepository.findByNomFruit("pomme") ;
	for (Fruit f : frui)
	{
	System.out.println(f);
	}
	}
	
	@Test
	public void testFindFruitByNomContains()
	{
	List<Fruit> frui = fruitRepository.findByNomFruitContains("p");
	for (Fruit f : frui)
	{
	System.out.println(f);
	}
	}
	
	@Test
	public void testfindByNomPrix()
	{
	List<Fruit> frui = fruitRepository.findByNomPrix("pomme", 1000.0);
	for (Fruit f : frui)
	{
	System.out.println(f);
	}
	}
	
	@Test
	public void testfindBySaison()
	{
	Saison sai = new Saison();

	sai.setIdSai(1L);
	
	List<Fruit> frui = fruitRepository.findBySaison(sai);
	for (Fruit p : frui)
	{
	System.out.println(p);
	}
	}
	
	@Test
	public void findBySaisonIdSai()
	{
	List<Fruit> prods = fruitRepository.findBySaisonIdSai(1L);
	for (Fruit p : prods)
	{
	System.out.println( p);
	}
	 }
	
	@Test
	public void testfindByOrderByNomFruitAsc()
	{
	List<Fruit> prods =fruitRepository.findByOrderByNomFruitAsc();
	for (Fruit p : prods)
	{
	System.out.println("apres le tri 1"+p);
	}
	}
	
	@Test
	public void testTrierFruitsNomsPrix()
	{
	List<Fruit> prods = fruitRepository.trierFruitsNomsPrix();
	for (Fruit p : prods)
	{
	System.out.println("apres le tri 22"+p);
	}
	}
}
 