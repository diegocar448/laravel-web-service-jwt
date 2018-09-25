<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected $fillable = [
        'name',
        'category_id',
        'description',
        'image',
    ];

    public function getResults($data, $total)
    {
        if(!isset($data['filter']) && !isset($data['name']) && !isset($data['description']))
        {
            return $this->paginate($total);
        }

        //criar filtro condicional
        return $this->where(function($query) use ($data){
            if(isset($data['filter'])){
                //após o filtro armazenar a variável
                $filter = $data['filter'];
                $query->where('name', $filter);
                $query->orWhere('description', 'LIKE', "%{$filter}%");
            }

            if(isset($data['name']))
            {
                $query->where('name', $data['name']);
            }

            if(isset($data['description']))
            {
                $description = $data['description'];
                $query->where('description', 'LIKE', "%{$description}%");
            }
        })
        ->paginate($total);


        //caso faça um debug da query executada no filtro
        /* $results =  $this->where(function($query) use ($data){
            if(isset($data['filter'])){
                //após o filtro armazenar a variável
                $filter = $data['filter'];
                $query->where('name', $filter);
                $query->orWhere('description', 'LIKE', "%{$filter}%");
            }

            if(isset($data['name']))
            {
                $query->where('name', $data['name']);
            }

            if(isset($data['description']))
            {
                $description = $data['description'];
                $query->where('description', 'LIKE', "%{$description}%");
            }
        })
        ->toSql();

        dd($results); */
        
    }

    //Uma categoria tem muitos produtos
    public function category()
    {
        return $this->belongsTo(Category::class);
    }
}
