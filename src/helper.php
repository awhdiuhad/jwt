<?php


 /**
 * @title 获取jwt值
 *
 * @param string $key key值
 */
function jwt(string $key) : mixed
{
    return \hush\facade\JWT::auth()[$key];
}

/**
 * @title 生成token
 * 
 * @param array $data 参数生成token的数组
 * @param bool $isArray 生成的token是否携带Bearer
 * 
 * @return string token
 */
function jwt_builder(array $data, bool $isCarry = true) : string
{
    return \hush\facade\JWT::builder($data, $isCarry);
}