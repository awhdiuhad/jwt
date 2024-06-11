<?php


return [
    // JWT加密算法
    'alg'        => env('JWT.ALG', 'HS256'),
    'secret'      => env('JWT.SECRET', 'hush'),
    // 非对称加密需要配置
    'public_key'  => env('JWT.PUBLIC_KEY'),
    'private_key' => env('JWT.PRIVATE_KEY'),
    'password'    => env('JWT.PASSWORD'),
    // JWT有效期
    'ttl'         => env('JWT.TTL', 3600 * 24 * 365),
];
