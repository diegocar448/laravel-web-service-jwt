<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthApiController extends Controller
{

    public function __constuct()
    {
        $this->middleware('auth:api', ['except' => 'authenticate']);
    }
    
    public function authenticate(Request $request)
    {
        // grab credentials from the request
        $credentials = $request->only('email', 'password');

        try {
            // attempt to verify the credentials and create a token for the user
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        //Pegar o usuários autenticado
        $user = auth()->user();

        // all good so return the token
        return response()->json(compact('token', 'user'));
    }


    // somewhere in your controller
    public function getAuthenticatedUser()
    {
        try {

            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

            return response()->json(['token_expired'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

            return response()->json(['token_invalid'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

            return response()->json(['token_absent'], $e->getStatusCode());

        }

        // the token is valid and we have found the user via the sub claim
        return response()->json(compact('user'));
    }

    //atualizar token
    public function refreshToken()
    {
        //se não passar o token no header então retorna o erro 401
        if(!$token = JWTAuth::getToken())
        {
            //dd("Entrou");
            return response()->json(['error' => 'token_not_send'], 401);        

           
        }

         try {
                $token = JWTAuth::refresh(); 
            }
        //retorna caso o token que foi passado seja invalido
        catch(Tymon\JWTAuth\Exceptions\TokenInvalidException $e){
            return response()->json(['token_invalid'], $e->getStatusCode());
        }

        return response()->json(compact('token'));
    }

}
