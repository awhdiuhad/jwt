<?php
declare(strict_types = 1);

namespace hush\middleware;

use hush\exception\JWTException;

class JWT
{
    public function handle($request, \Closure $next)
    {
        try {
            (new \hush\JWT())->validate();
            return $next($request);
        } catch (JWTException $e) {
            return json(['code' => 0, 'msg' => $e->getMessage()]);
        }
    }
}
