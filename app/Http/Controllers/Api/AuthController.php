<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Resources\UserResource;
use App\Models\PasswordReset;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Hash;
use App\Notifications\PasswordResetNotification;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;


class AuthController extends Controller
{
    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
    
        if ($user) {
            $user->tokens()->delete();
            return response()->success([], 'Logged out successfully', 200);
        } else {
            return response()->error('Unauthorized', 'User not authenticated', 401);
        }
    }
    public function register(Request $request):JsonResponse
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:8',
        ]);

        $attributes = $request->only(app(User::class)->getFillable());

    $attributes['password'] = Hash::make($attributes['password']);

    $user = User::create($attributes);

    $token = $user->createToken('authToken')->plainTextToken;

    $response = [
        'users' => UserResource::make($user),
        'token' => $token
    ];

    return response()->success($response, 'User registered successfully', 201);
    }

public function login(Request $request){
    $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    $user = User::where('email', $request->get('email'))->first();

    if (!$user || !Hash::check($request->password, $user->password)) {
        return response()->error('Invalid Credentials', 'No record found', 401);
    }

    $token = $user->createToken('authToken')->plainTextToken;

    $response = [
        'user' => UserResource::make($user),
        'token' => $token
    ];

    return response()->success($response, 'User logged in successfully', 201);
}

    public function forgot(ForgotPasswordRequest $request)
    {
        $request->validated();

    $user = User::where('email', $request->input('email'))->first();

        if(!$user || !$user->email){
            return response()->error('No Record Found', 'Incorrect Email Adress Provided', 404);
        }

        $resetPasswordToken = str_pad(random_int(1,9999),4,'0', STR_PAD_LEFT);

        if(!$userPassReset =PasswordReset::where('email', $user->email)->first()){
            PasswordReset::create([
                'email' => $user->email,
                'token' => $resetPasswordToken,
            ]);
        }else{
            $userPassReset->update([
                'email' => $user->email,
                'token' => $resetPasswordToken,
            ]);
        }
        
        $user->notify(
            new PasswordResetNotification($resetPasswordToken)
        );

        return response()->json(['message' => 'A code has been sent to your email address']);
    }

    public function reset(ResetPasswordRequest $request):JsonResponse
    {   
        $attributes = $request->validated();

        $user = User::where('email', $attributes['email'])->first();


        if(!$user){
            return response()->error('No Record Found', 'Incorrect Email Adress Provided', 404);
        }

        $resetRequest = PasswordReset::where('email', $user->email)->first();

        if($resetRequest || $resetRequest->token !== $request->token){
            return response()->error('An Error Occured', 'Please Try Again','Token Mismatch', 404);
        }

        $user->fill([
            'password' => Hash::make($attributes['password']),
        ]);
        $user->save();

        $user->tokens()->delete();

        $resetRequest->delete();

        $token = $user->createToken('authToken')->plainTextToken;

        $loginResponse = [
            'user'  => new UserResource($user),
            'token' => $token,
        ];

            return response()->json($loginResponse, 201);

    }

}