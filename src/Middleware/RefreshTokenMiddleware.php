<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Respect\Validation\Validator as v;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\AuthResult;
use Mauricek\PsrAuthentication\LoginValidator;
use Mauricek\PsrAuthentication\Exception\InvalidArgumentException;
use Mauricek\PsrAuthentication\Exception\RuntimeException;

class RefreshTokenMiddleware implements MiddlewareInterface
{
    protected $authenticate;

    public function  __construct(
        Authenticate $authenticate
    ) {
        $this->authenticate = $authenticate;
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {
        $body = $request->getParsedBody();

        isset($body['refresh_token']) && $input['refresh_token'] = filter_var($body['refresh_token'], FILTER_SANITIZE_STRING);
        $rule = v::arrayType()->key('refresh_token', v::stringType()->notEmpty()->uuid());

        try {
            $rule->assert($body);
        } catch(NestedValidationException $e) {
            throw InvalidArgumentException('Validation - ', null, $e);
        }

        $authResult = $this->authenticate->refresh($input['refresh_token']);

        if(!$authResult->success()) {
            throw new RuntimeException('Unauthorized refresh attempt - '.(string)$authResult->reason());
        }

        $credentials = new Credentials(
            $authResult->member()->id(),
            $authResult->member()->username(),
            $authResult->role()
        );

        $request = $request->withAttribute(Credentials::class, $credentials);

        return $delegate->handle($request);
    }
}
