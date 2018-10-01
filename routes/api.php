<?php

/* $this->get('categories', 'Api\CategoryController@index');

$this->post('categories', 'Api\CategoryController@store');

$this->put('categories/{id}', 'Api\CategoryController@update');

$this->delete('categories/{id}', 'Api\CategoryController@delete'); */

/* $this->resources('categories', 'Api\CategoryController', [
    'except' => ['edit', 'create']
]); */


//gerar o token
$this->post('auth', 'Auth\AuthApiController@authenticate');

//atualizar token
$this->post('auth-refresh', 'Auth\AuthApiController@refreshToken');

//recuperar usuario passando na header o token
$this->get('me', 'Auth\AuthApiController@getAuthenticatedUser');



$this->group([
    'prefix' => 'v1', 
    'namespace' => 'Api\v1',
    'middleware' => 'jwt.auth', 
    //para deixar obrigatorio passar o token valido sempre que tentar acessar a rota
], function(){

    //Retornar todos os produtos de uma determinada categoria
    $this->get('categories/{id}/products', 'CategoryController@products');

    $this->apiResource('categories', 'CategoryController');

    $this->apiResource('products', 'ProductController');
});




