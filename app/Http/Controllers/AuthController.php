<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Support\Facades\Hash;
use App\Notifications\SignupActivate;
use App\Notifications\SignupNotification;
use App\User;
use Auth;
use Validator;
use Str;

class AuthController extends Controller
{
    use AuthenticatesUsers;
    public function login(Request $request)
    {
        
        $status = 401;
        $response = ['error' => 'Unauthorised'];
        if (Auth::attempt($request->only(['email', 'password']))) {
            if (User::where('email', $request['email'])->first()) {
                $status = 200;
                $response = [
                    'user' => Auth::user(),
                    'token' => Auth::user()->createToken('accessToken')->accessToken,
                ];
                return response()->json($response, $status);
            }
            else {
                return response()->json(['message' => 'No User with that email']);
            } 
        }
        else {
            return response()->json(['message' => 'Invalid Email Or Password']);
        }
        
    }
    public function register(Request $request)
    {
        // User Data to validate
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'username' => 'required|unique:users',
            'phone' => 'required',
            'wallet_address' => 'required',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed|min:8',
            'user_type' => 'integer',
            // 'city' => 'required',
            // 'state' => 'required',
            // 'country' => 'required',
            // 'address' => 'required'
        ]);
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }
        $data = $request->only([
            'name', 
            'username',
            'phone',  
            'wallet_address',
            // 'city',
            // 'state',
            // 'country',
            // 'address',
            'email', 
            'password',
            'user_type',
        ]);
        $data['password'] = bcrypt($data['password']);
        $data['user_type'] = User::DEFAULT_TYPE;
        //$data['activation_token'] = Str::random(60);
        $admin = User::where('user_type', 1)->get();
        $user = User::create($data);
        if ($user) {
            $user->notify(new SignUpActivate($user));
            foreach ($admin as $key => $value) {
                $value->notify(new SignupNotification($user));
            }
            return response()->json([
                'user' => $user,
                'token' => $user->createToken('accessToken')->accessToken,
                'status' => 200
            ]);
        }
        else {
            return response('Creation error', 400);
        }
        

        
    }

    // ADMIN REGISTER
    public function adminRegister(Request $request)
    {
        // User Data to validate
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'username' => 'required|unique:users',
            'phone' => 'required',
            'wallet_address' => 'required',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed|min:8',
            'user_type' => 'integer',
        ]);
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        }
        $data = $request->only([
            'name', 
            'username',
            'phone',  
            'wallet_address',
            'email', 
            'password',
            'user_type'
        ]);
        $data['password'] = bcrypt($data['password']);
        $data['user_type'] = User::ADMIN_TYPE;
        $user = User::create($data);
        return response()->json([
            'user' => $user,
            'token' => $user->createToken('accessToken')->accessToken,
            'status' => 200
        ]);
    }

     /**
     * This function request for old password in order to change to new one
     */
    public function changePassword(Request $request)
    {
        $status = 401;
        $response = ['error' => 'Unauthorised'];
        $user = Auth::user();
        if ($user) {
            $password = $user->password;
            $old_pass = $request->currentPass; 
            if (Hash::check($old_pass, $password )) {
                // The passwords match...
                $data = $request->newPass;
                
                $newPass = $request->user()->fill([
                    'password' => Hash::make($data)
                ])->save();
                return response()->json([
                    'user' => $newPass,
                    'message' => 'Password Changed Successfully'
                ]);
            }
            else {
                return response()->json(['error' => $status]);
            }
        }
        else {
            return response()->json($response);
        }
    }

    // public function signupActivate($token)
    // {
    //     $user = User::where('activation_token', $token)->first();
    //     if (!$user) {
    //         return response()->json([
    //             'message' => 'This activation token is invalid.'
    //         ], 404);
    //     }
    //     $user->active = true;
    //     $user->activation_token = '';
    //     $user->save();
    //     return $user;
    // }
}
