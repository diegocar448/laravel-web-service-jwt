<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Category extends Model
{

    protected $fillable = ['name'];


    public function getResults($name = null)
    {
        if(!$name)
        {
            return $this->get();
        }

        return $this->where('name', 'LIKE', "%{$name}%")
            ->get();   
    }


    //Muitos produtos tem muitas categoria
    public function products()
    {
        return $this->hasMany(Product::class);
    }

}
