<?php
namespace Rinzler\UserEncryption\Models;

use Illuminate\Database\Eloquent\Model;

class UserEncryption extends Model
{
    protected $table = 'user_encryption';

    public function user()
    {
        return $this->belongsTo('App\User');
    }
}