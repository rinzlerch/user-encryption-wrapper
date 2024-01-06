<?php
namespace Rinzler\UserEncryption\Http;

use Illuminate\Http\Request;
use Crypton\Http\Requests;
use Crypton\User;
use Auth;
use Rinzler\UserEncryption\Support\UserEncryption;
use Rinzler\UserEncryption\Models\UserEncryption as UserEncrypt; 
use Cookie;

class UserEncryptionController
{
	public function rules() {
	    return [
	      'passphrase' => 'required',
	    ];
	}

    public function new(Request $request) {
    	$encryption = new UserEncryption;
        $key = $encryption->generateEncryptionKey($request->passphrase);
        $AESKey = $encryption->generateAESKey();
        $user = User::where('id', Auth::id())->firstOrFail();

        $userEncrypt = new UserEncrypt;
        $userEncrypt->belongs_to = Auth::id();
        $userEncrypt->master_public_key = $key['public'];
        $userEncrypt->master_private_key = $key['private'];
        $userEncrypt->encryption_public_key = $AESKey['public'];
        $userEncrypt->encryption_private_key = $encryption->encryptAESKey($AESKey['private'], base64_decode($key['public']));
        $userEncrypt->save();

        $masterKey = $encryption->decryptMasterKey($user->encryption->master_private_key, $request->passphrase);
        $decryptedAESKey = $encryption->decryptAESKey($user->encryption->encryption_private_key, $masterKey);
        
        $cookie = Cookie::make('secret_key-'.$user->uuid, encrypt($decryptedAESKey), 43800); //1 month
        return back()->withCookie($cookie);
    }

    public function decryptOnLogin(Request $request) {
    	$encryption = new UserEncryption;
        $user = UserEncrypt::where('belongs_to', Auth::id())->firstOrFail();
        $userActual = User::where('id', Auth::id())->firstOrFail();
        $masterKey = $encryption->decryptMasterKey($user->master_private_key, $request->passphrase);
        if (!$masterKey) {
            return redirect()->back()->with('message', __('auth/passphrase/decrypt.error_msg'));
        } else {
            $decryptedAESKey = $encryption->decryptAESKey($user->encryption_private_key, $masterKey);
        }

        $cookie = Cookie::make('secret_key-'.$userActual->uuid, encrypt($decryptedAESKey), 43800); //1 month
        return back()->withCookie($cookie);
    }
}
