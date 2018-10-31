<?php
Route::group(['prefix' => 'encryption', 'as' => 'user-encryption.', 'middleware' => 'web'], function () {
    Route::post('new', '\Rinzler\UserEncryption\Http\UserEncryptionController@new')->name('new');
    Route::post('decrypt', '\Rinzler\UserEncryption\Http\UserEncryptionController@decryptOnLogin')->name('decrypt');
});