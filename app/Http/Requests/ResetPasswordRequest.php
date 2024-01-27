<?php

namespace App\Http\Requests;

use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;

class ResetPasswordRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize()
    {
        return !($user = auth()->user()) ||
        !($user instanceof User);
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules()
    {
        return [
            'email' => [
                'requred',
                'exists:users,email', 
            ],
            'token' => [
                'required'
            ],
            'password' => [
                'required',
                'min:6',
                'confirmed'
            ]
        ];
    }
}
