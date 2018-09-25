<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreUpdateProductFormRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        //Sempre adicionar true quando for iniciar as validações
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {   //segment pega o valor pela posição do paramentro na url
        $id = $this->segment(3);
        return [              //verificar se a chave estrangeira existe na tabela categories
             'category_id' => "required|exists:categories,id",              
             //'name'        => "required|min:3|max:10|unique:products,name,{$this->id}",
             'name'        => "required|min:3|max:10|unique:products,name,{$id},id",
             'description' => 'max:1000',
             'image'       => 'image',
        ];
    }
}
 