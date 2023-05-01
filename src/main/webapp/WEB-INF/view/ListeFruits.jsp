<%@ page language="java" contentType="text/html; charset=windows-1256"
 pageEncoding="windows-1256"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css"/>
<c:url value="/css/main.css" var="jstlCss" />
<link href="${jstlCss}" rel="stylesheet" />
<script type="text/javascript"
src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.min.js"></script>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1256">
<title>Liste Fruits</title>
</head>
<body>
<div class="container mt-5">
<div class="card">
 <div class="card-header">
 Liste des Fruits
 </div>
 <div class="card-body">
 
 <table class="table table-striped">
 <tr>
<th>ID</th><th>Nom Fruit</th><th>Prix</th><th>Date 
debut saison</th><th>Suppression<th>Edition</th>
 </tr>
 <c:forEach items="${fruits}" var="p">
 <tr>
 <td>${p.idFruit }</td>
 <td>${p.nomFruit }</td>
 <td>${p.prixFruit }</td>
 <td><fmt:formatDate pattern="dd/MM/yyyy"
value="${p.dateDebSaison}" /></td>
 <td><a onclick="return confirm('Etes-vous sûr ?')"
href="supprimerFruit?id=${p.idFruit }">Supprimer</a></td>
 <td><a href="modifierFruit?id=${p.idFruit }">Edit</a></td>
 </tr>
 </c:forEach> 
 </table>
 </div>
</div>
</div>
</body>
</html>
