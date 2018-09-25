<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
//Aqui definimos a quantidade padrão de caracteres para as 
//colunas de nossas tabelas
use Illuminate\Support\Facades\Schema;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //Aqui definimos a quantidade padrão de caracteres para as 
        //colunas de nossas tabelas
        Schema::defaultStringLength(191);
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
