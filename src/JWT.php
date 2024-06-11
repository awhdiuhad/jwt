<?php
declare(strict_types = 1);

namespace hush;

use hush\exception\JWTAlgException;
use hush\exception\JWTBadMethodCallException;
use hush\exception\JWTConfigException;
use hush\exception\JWTException;
use hush\exception\JWTTokenInvalidException;
use hush\exception\JWTTokenNotFoundException;
use hush\exception\JWTUserException;

class JWT
{
    // 默认配置
    protected $config = [
        // JWT加密算法
        'alg'        => 'HS256',
        'secret'      => 'hush',
        // 非对称需要配置
        'public_key'  => '',
        'private_key' => '',
        'password'    => '',
        // JWT有效时间
        'ttl'         => 3600 * 24 * 365,
    ];

    // 标准声明
    protected array $standardClaim = [
        'iss' => null,
        'sub' => null,
        'aud' => null,
        'exp' => null,
        'nbf' => null,
        'iat' => null,
        'jti' => null,
    ];

    // 公共声明
    protected array $publicClaim = [];

    // 私有声明，暂时留空
    protected array $privateClaim = [];

    // 算法类型
    protected array $algorithm = [
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512'
    ];

    // header部分
    protected array $header = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];

    // payload部分
    protected array $payload = [];

    // 签证信息
    protected array $signature = [];

    public function __construct()
    {
        $this->config = array_merge($this->config, config('jwt'));
    }

    /**
     * @title 生成token
     *
     * @param array $user 用户信息
     * @param bool $isCarry 生成的token是否携带Bearer
     *
     * @return string token字符串
     * @throws JWTAlgException
     * @throws JWTUserException
     * @throws JWTConfigException
     */
    public function builder(array $user, bool $isCarry = true): string
    {
        $this->publicClaim = $user;
        $header = $this->getHeader();
        $payload = $this->getPayLoad($user);
        $signature = $this->getSignature($header, $payload);
        $token = $header . '.' . $payload . '.' . $signature;
        return $isCarry ? 'Bearer ' . $token : $token;
    }

    /**
     * @title 获取header部分
     *
     * @return string header
     * @throws JWTAlgException
     */
    protected function getHeader(): string
    {
        if (!in_array(strtoupper($this->config['alg']), $this->algorithm)) {
            throw new JWTAlgException("Algorithm [{$this->config['alg']}] does not exist.");
        }
        // 目前仅支持hs256
        if (strtoupper($this->config['alg']) != 'HS256') {
            throw new JWTAlgException("only HS256 algorithm is supported.");
        }
        $this->header['alg'] = strtoupper($this->config['alg']);
        return base64_encode(json_encode($this->header));
    }

    /**
     * @title 获取payload部分
     *
     * @param array $user 用户信息
     *
     * @return string payload
     * @throws JWTUserException
     * @throws JWTConfigException
     */
    protected function getPayLoad(array $user): string
    {
        if (!is_array($user)) {
            throw new JWTUserException("user info type is not array.");
        }

        $userKeyArray = array_keys($user);
        $standardClaimKeyArray = array_keys($this->standardClaim);
        $intersect = array_intersect($userKeyArray, $standardClaimKeyArray);
        if ($intersect) {
            $intersectString = implode(',', $intersect);
            throw new JWTUserException("user info [{$intersectString}] does not allowed to use.");
        }

        if (!is_numeric($this->config['ttl'])) {
            throw new JWTConfigException("jwt config [ttl] invalid.");
        }
        $this->standardClaim['exp'] = time() + $this->config['ttl'];
        $payloadArray = array_merge($this->standardClaim, $user);
        return base64_encode(json_encode($payloadArray));
    }

    /**
     * @title 获取签证部分
     *
     * @param string $header header部分
     * @param string $payload payload部分
     *
     * @return string signature
     */
    protected function getSignature(string $header, string $payload): string
    {
        $signature = $header . '.' . $payload;
        return hash_hmac('sha256', $signature, $this->config['secret']);
    }

    /**
     * @title 验证token是否有效（仅验证时间和加密方式）
     *
     * @return bool 布尔值
     * @throws JWTTokenNotFoundException
     * @throws JWTTokenInvalidException
     */
    public function validate(): bool
    {
        $tokenBearer = app('request')->header('authorization');
        if (!$tokenBearer) {
            throw new JWTTokenNotFoundException('token不能为空');
        }
        $token = substr($tokenBearer, 7);
        if (!$token) {
            throw new JWTTokenNotFoundException('token格式不正确');
        }

        $tokenArray = explode('.', $token);
        if (count($tokenArray) != 3) {
            throw new JWTTokenInvalidException('token需要有俩个点');
        }

        $signature = hash_hmac('sha256', $tokenArray[0] . '.' . $tokenArray[1], $this->config['secret']);
        if ($signature != $tokenArray[2]) {
            throw new JWTTokenInvalidException('token无效');
        }
        $payloadArray = json_decode(base64_decode($tokenArray[1]), true);
        if ($payloadArray['exp'] < time()) {
            throw new JWTTokenInvalidException('token已过期');
        }
        return true;
    }

    /**
     * @title 获取信息对象
     *
     * @return object 信息对象
     */
    public function auth(): object
    {
        $user = new class() implements \ArrayAccess {
            public function offsetExists($offset)
            {
                return isset($this->$offset);
            }

            public function offsetGet($offset)
            {
                return $this->$offset;
            }

            public function offsetSet($offset, $value)
            {
                $this->$offset = $value;
            }

            public function offsetUnset($offset)
            {
                unset($this->$offset);
            }

            public function __get($name)
            {
                return null;
            }
        };

        try {
            $this->validate();
            $tokenBearer = app('request')->header('authorization');
            $token = substr($tokenBearer, 7);
            $tokenArray = explode('.', $token);
            $payloadArray = json_decode(base64_decode($tokenArray[1]), true);
            foreach ($payloadArray as $k => $v) {
                $user->$k = $v;
            }
            return $user;
        } catch (JWTException $e) {
            $user->_error_msg = $e->getMessage();
            return $user;
        }
    }

    /**
     * @title 调用没有的方法触发
     *
     * @param string $name 方法名
     * @param mixed $arguments 方法参数
     *
     * @throws JWTBadMethodCallException
     */
    public function __call(string $name, mixed $arguments)
    {
        throw new JWTBadMethodCallException("方法 [$name]不存在");
    }
}