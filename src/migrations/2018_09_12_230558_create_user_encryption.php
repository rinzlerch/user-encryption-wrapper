<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateUserEncryption extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        if (!Schema::hasTable('user_encryption')) {
            Schema::create('user_encryption', function (Blueprint $table) {
                $table->increments('id');
                $table->string('belongs_to');
                $table->text('master_private_key');
                $table->text('master_public_key');
                $table->text('encryption_private_key');
                $table->text('encryption_public_key');
                $table->timestamps();
            });
        }
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('user_encryption');
    }
}
