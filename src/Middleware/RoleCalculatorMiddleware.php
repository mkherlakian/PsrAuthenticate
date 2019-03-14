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

class RoleCalculatorMiddleware implements MiddlewareInterface
{
    private $roleCalculator;

    public function __construct(
        RoleCalculator $roleCalculator,
        CanRetrieveMember $memberAdapter
    ) {
        $this->roleCalculator = $roleCalculator;
        $this->memberAdapter = $memberAdapter;
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

        $memberId       = $credentials->memberId();
        $role           = $credentials->role();
        $user           = $credentials->username();

        $member         = $this->memberAdapter->retrieveMemberById($memberId);
        $newRole        = $this->roleCalculator->calculateRole($member, $role);

        $credentials    = $credentials->withRole($newRole);
        $request        = $request->withAttribute(Credentials::class, $credentials);

        return $delegate->handle($request);
    }
}
