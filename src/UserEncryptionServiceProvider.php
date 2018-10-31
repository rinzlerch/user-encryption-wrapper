<?php

namespace Rinzler\UserEncryption;

use Illuminate\Support\ServiceProvider;

class UserEncryptionServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        include __DIR__.'/routes/web.php';

        $this->publishes([
            __DIR__ . '/migrations' => $this->app->databasePath() . '/migrations'
        ], 'userencryption');

        // Run "php artisan vendor:publish --tag=userencryption" to publish.
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->make('Rinzler\UserEncryption\Http\UserEncryptionController');
        $this->app->bind('UserEncryption', 'Rinzler\UserEncryption\UserEncryption' );
    }
}
