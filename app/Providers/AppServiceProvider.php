<?php

namespace App\Providers;

use Illuminate\Support\Facades\Response;
use Illuminate\Auth\Access\Response as AccessResponse;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Response::macro('success', function($data,$message, $status_code = 200){
            return response()->json([
                'success' => true,
                'message' => $message,
                'data' => $data
            ],$status_code);
        });


        Response::macro('error', function ($message, $error, $status_code = 400) {
            return response()->json([
                'success' => false,
                'message' => $message,
                'error' => $error,
            ], $status_code);
        });
    }
}
