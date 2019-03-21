<?php

namespace MauricekTest\PsrAuthentication\Unit\Middleware;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\Middleware\ChainedAuthValidationMiddleware;
use Mauricek\PsrAuthentication\AuthProvider\AuthValidationProvider;
use Mauricek\PsrAuthentication\Credentials;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Prophecy\Argument;


class ChainedAuthMiddlewareTest extends TestCase
{
    public function setUp() {
        $pm = $this->prophesize(AuthProviderPluginManager::class);
        $provider1 = $this->prophesize(AuthValidationProvider::class);

        $provider1
            ->validate(Argument::type(ServerRequestInterface::class))
            ->shouldBeCalled()
            ->willReturn(null);

        $provider2 = $this->prophesize(AuthValidationProvider::class);
        $provider2
            ->validate(Argument::type(ServerRequestInterface::class))
            ->shouldBeCalled()
            ->willReturn(new Credentials('1234', 'usrname', 'member'));

        $this->chainedAuthMw = new ChainedAuthValidationMiddleware(
            $provider1->reveal(),
            $provider2->reveal()
        );
    }

    public function testValidateSuccess()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request
            ->withAttribute(Credentials::class, new Credentials('1234', 'usrname', 'member'))
            ->shouldBeCalledTimes(1)
            ->willReturn($request);

        $response = $this->prophesize(ResponseInterface::class);

        $delegate = $this
            ->prophesize(RequestHandlerInterface::class);
        $delegate->handle(Argument::any())
            ->willReturn($response->reveal());


        $this->chainedAuthMw->process($request->reveal(), $delegate->reveal());
    }

}
