<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\HtmlResponse;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Expressive\Router\RouteResult;
use Assert\Assertion;

class BlacklistTokenOnWriteMiddleware implements MiddlewareInterface
{
    protected $authenticate;

    public function  __construct(
        Authenticate $authenticate,
        array $config
    ) {
        $this->authenticate = $authenticate;

        Assertion::keyExists($config, 'invalidate_token_on_write');
        $this->blacklistTokenAfterWrite = $config['invalidate_token_on_write'];
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {
        $response = $delegate->handle($request);

        //If request is write (POST, PUT, DELETE), and reponse is 200,
        //blacklist token - helps prevent replay attacks
        if(in_array($request->getMethod(), ['POST', 'PUT', 'DELETE', 'PATCH'])
            && $response->getStatusCode() == 200
            && $this->blacklistTokenAfterWrite
        ) {
            $jti = $request->getAttribute(TokenJti::class);
            $exp = $request->getAttribute(TokenExp::class);

            $this->authenticate->blacklistToken($jti, $exp);
        }

        return $response;
    }
}
