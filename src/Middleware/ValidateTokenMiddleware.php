<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Mauricek\PsrAuthentication\Exception\InvalidArgumentException;
use Mauricek\PsrAuthentication\Exception\RuntimeException;
use Mauricek\PsrAuthentication\AuthProvider\JwtValidationProvider;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response\HtmlResponse;
use Zend\Diactoros\Response\EmptyResponse;
use Zend\Expressive\Router\RouteResult;

class ValidateTokenMiddleware implements MiddlewareInterface
{
    protected $validationProvider;

    public function  __construct(
        JwtValidationProvider $validationProvider
    ) {
        $this->validationProvider   = $validationProvider;
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {
        $credentials = $this->validationProvider->validate($request);

        if(is_null($credentials)) {
            throw new RuntimeException('Validation failed - invalid token');
        }

        $request = $request
            ->withAttribute(Credentials::class, $credentials);

        $response = $delegate->handle($request);

        return $response;
    }

}
