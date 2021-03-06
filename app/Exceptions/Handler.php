<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array
     */
    protected $dontFlash = [
        'password',
        'password_confirmation',
    ];

    /**
     * Report or log an exception.
     *
     * @param  \Exception  $exception
     * @return void
     */
    public function report(Exception $exception)
    {
        parent::report($exception);
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $exception
     * @return \Illuminate\Http\Response
     */
    public function render($request, Exception $exception)
    {
        //personalizar o erro
        //dd($exception);
        if($exception instanceof \Symfony\Component\HttpKernel\Exception\NotFoundHttpException ){
            //se a requisição retornar em JSON(expectsJson) ou seja um ajax então
            if($request->expectsJson())
                return response()->json(['error' => 'Nao encontrou nada'], $exception->getStatusCode());
        }

        //tratar erro caso a rota receba um verbo http errado
        if($exception instanceof \Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException ){
            //se a requisição retornar em JSON(expectsJson) ou seja um ajax então
            if($request->expectsJson())
                return response()->json(['error' => 'Metodo nao permitido'], $exception->getStatusCode());
        }


        //Tratamento para caso o token seja expirado
        if ($exception instanceof Tymon\JWTAuth\Exceptions\TokenExpiredException) {
		    return response()->json(['token_expired'], $exception->getStatusCode());
        }
        
        if ($exception instanceof Tymon\JWTAuth\Exceptions\TokenInvalidException) {
            return response()->json(['token_invalid'], $exception->getStatusCode());
        }


        return parent::render($request, $exception);
    }
}
