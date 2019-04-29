<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\MemberAdapter\CanRetrieveMember;
use Mauricek\PsrAuthentication\RoleCalculator\RoleCalculator;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;

class RefreshTokenUpdateMiddleware implements MiddlewareInterface
{
    protected $authStore;

    public function __construct(AuthStore $authStore)
    {
        $this->authStore = $authStore;
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $delegate
    ) : ResponseInterface {
        $credentials   = $request->getAttribute(Credentials::class);

        if(is_null($credentials))  {
            throw new Problems\ServerError(
                sprintf("No %s found in request", Credentials::class),
                'missing_credentials'
            );
        }

        if(is_null($credentials->refreshToken())) {
            throw new Problems\ServerError(
                sprintf("No refreshToken in Credentials"),
                'missing_refresh_token'
            );
        }

        $role       = $credentials->role();

        //Update refresh token
        $this->authStore->updateRole($credentials->memberId(), $role);

        return $delegate->handle($request);
    }
}
