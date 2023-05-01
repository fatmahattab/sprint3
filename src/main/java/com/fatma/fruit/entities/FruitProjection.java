package com.fatma.fruit.entities;

import org.springframework.data.rest.core.config.Projection;

@Projection(name = "nomFrui", types = { Fruit.class })
public interface FruitProjection {
	public String getNomFruit();

}
