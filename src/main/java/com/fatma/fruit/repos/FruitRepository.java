package com.fatma.fruit.repos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.entities.Saison;

@RepositoryRestResource(path = "rest")
public interface FruitRepository extends JpaRepository<Fruit, Long> {
	List<Fruit> findByNomFruit(String nom);
	 List<Fruit> findByNomFruitContains(String nom);
	 @Query("select f from Fruit f where f.nomFruit like %:nom and f.prixFruit > :prix")
	 List<Fruit> findByNomPrix (@Param("nom") String nom,@Param("prix") Double prix);
	 @Query("select p from Fruit p where p.saison = ?1")
	 List<Fruit> findBySaison (Saison saison);
	 
	 List<Fruit> findBySaisonIdSai(Long id);
	 List<Fruit> findByOrderByNomFruitAsc();
	 @Query("select p from Fruit p order by p.nomFruit ASC, p.prixFruit DESC")
	 List<Fruit> trierFruitsNomsPrix ();

}
