package com.fatma.fruit.controllers;

import java.text.ParseException;



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fatma.fruit.entities.Fruit;
import com.fatma.fruit.entities.Saison;
import com.fatma.fruit.service.FruitService;

import jakarta.validation.Valid;

@Controller
public class FruitController {
@Autowired
FruitService fruitService;
@RequestMapping("/showCreate")
public String showCreate(ModelMap modelMap)
{
	List<Saison> cats = fruitService.getAllSaison();
	Fruit prod = new Fruit();
	Saison cat = new Saison();
	cat = cats.get(0); 
	prod.setSaison(cat); 
	modelMap.addAttribute("fruit",prod);
	modelMap.addAttribute("mode", "new");
	modelMap.addAttribute("saisons", cats);
	return "formFruit";
	
	
}
/*@RequestMapping("/saveFruit")
public String saveFruit(@ModelAttribute("fruit") Fruit fruit, 
 @RequestParam("date") String date,
 ModelMap modelMap) throws
ParseException 
{
//conversion de la date 
	 SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
	 Date dateDebSaison = dateformat.parse(String.valueOf(date));
	 fruit.setDateDebSaison(dateDebSaison);
 
Fruit saveFruit = fruitService.saveFruit(fruit);
String msg ="fruit enregistré avec Id "+saveFruit.getIdFruit();
modelMap.addAttribute("msg", msg);
return "createFruit";
}*/

@RequestMapping("/saveFruit")
public String saveFruit(@Valid Fruit fruit,
		 BindingResult bindingResult,@RequestParam(name="page",defaultValue="0")int page,
		 @RequestParam(name="size",defaultValue="02")int size,RedirectAttributes redirectAttributes)
{
	if (bindingResult.hasErrors()) return "formFruit";

 fruitService.saveFruit(fruit);
 Page<Fruit>frui=fruitService.getAllFruitsParPage(page, size);
 page=frui.getTotalPages()-1;
 redirectAttributes.addAttribute("page", page);
 
return "redirect:/ListeFruits";
}

@RequestMapping("/ListeFruits")
public String ListeFruits(ModelMap modelMap,
		@RequestParam (name="page",defaultValue = "0") int page,
		@RequestParam (name="size", defaultValue = "2") int size)

{
	Page<Fruit> frui = fruitService.getAllFruitsParPage(page, size);
	modelMap.addAttribute("fruits", frui);
	 modelMap.addAttribute("pages", new int[frui.getTotalPages()]);
	modelMap.addAttribute("currentPage", page);
return "ListeFruits";
}

@RequestMapping("/supprimerFruit")
public String supprimerFruit(@RequestParam("id") Long id,
 ModelMap modelMap,
 @RequestParam (name="page",defaultValue = "0") int page,
 @RequestParam (name="size", defaultValue = "2") int size)
{ 
	fruitService.deleteFruitById(id);
	Page<Fruit> frui = fruitService.getAllFruitsParPage(page, 
	size);
	modelMap.addAttribute("fruits", frui);
	modelMap.addAttribute("pages", new int[frui.getTotalPages()]);
	modelMap.addAttribute("currentPage", page);
	modelMap.addAttribute("size", size);
return "ListeFruits";
}


@RequestMapping("/modifierFruit")
public String editerFruit(@RequestParam("id") Long id,ModelMap modelMap)
{
	Fruit p= 	fruitService.getFruit(id);
	List<Saison> cats = fruitService.getAllSaison();
	
	
	modelMap.addAttribute("fruit", p);
	modelMap.addAttribute("mode", "edit");
	modelMap.addAttribute("saisons", cats);
	return "formFruit";		
	
	
//Fruit f= fruitService.getFruit(id);
//modelMap.addAttribute("fruit", f);
//modelMap.addAttribute("mode", "edit");
//return "formFruit";

}
@RequestMapping("/updateFruit")
public String updateFruit(@ModelAttribute("fruit") Fruit fruit,
@RequestParam("date") String date,ModelMap modelMap) throws ParseException 
{
	//conversion de la date 
	 SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
	 Date dateDebSaison = dateformat.parse(String.valueOf(date));
	 fruit.setDateDebSaison(dateDebSaison);
	 
	 fruitService.updateFruit(fruit);
	 List<Fruit> frui = fruitService.getAllFruits();
	 modelMap.addAttribute("fruits", frui);
	 return "ListeFruits";
	}


}
