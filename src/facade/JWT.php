<?php
declare(strict_types = 1);

namespace hush\facade;

use think\Facade;

/**
 * @title JWT的门面
 *
 * @method string builder(array $user, bool $isCarry = true) static 创建token
 * @method bool validate() static 是否认证通过
 * @method object auth() static 获取信息
 */
class JWT extends Facade
{
    protected static function getFacadeClass()
    {
        return \hush\JWT::class;
    }
}
