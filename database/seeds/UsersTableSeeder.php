<?php

use Illuminate\Database\Seeder;
use App\User;

class UsersTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        User::create([
            'name' => 'Diego Cardoso',
            'email' => 'diegocar@hotmail.com',
            'password' => bcrypt('123456'),
        ]);
    }
}